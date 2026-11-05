package sweep

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"keyguard/internal/core"
)

// blobIDs lists the blobs a range reaches, as git does for a scan: rev-list --objects into
// cat-file --batch-check. It is what the ledger needs from an engine's range: engines read
// commits through their own git and never hand blobs back, so the only way to know whether a
// range holds anything an engine has not seen is to list its blobs here.
//
// The listing is ids only. No content is read, and an unreadable object ends the listing with
// an error instead of a short list that would pass for "nothing new".
func blobIDs(ctx context.Context, git, repo string, args []string) ([]oid, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	list := gitCmd(ctx, git, repo, slices.Concat([]string{"rev-list", "--objects"}, args, []string{"--"})...)
	check := gitCmd(ctx, git, repo, "cat-file", "--batch-check="+batchFormat)
	var listErr, checkErr tailBuffer
	list.Stderr, check.Stderr = &listErr, &checkErr

	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer pr.Close()
	defer pw.Close()
	list.Stdout, check.Stdin = pw, pr
	out, err := check.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := list.Start(); err != nil {
		return nil, fmt.Errorf("sweep: start git rev-list: %w", err)
	}
	pw.Close() // the child owns the write end now
	if err := check.Start(); err != nil {
		cancel()
		list.Wait()
		return nil, fmt.Errorf("sweep: start git cat-file: %w", err)
	}
	pr.Close()

	var ids []oid
	br := bufio.NewReaderSize(out, 256<<10)
	var readErr error
	for {
		line, err := br.ReadString('\n')
		if h, ok := parseHeader(line); ok && h.typ == "blob" {
			if id, ok := parseOID(h.sha); ok {
				ids = append(ids, id)
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
			}
			break
		}
	}
	if readErr != nil {
		cancel()
	}
	for _, p := range []struct {
		c    interface{ Wait() error }
		name string
		err  *tailBuffer
	}{{list, "rev-list", &listErr}, {check, "cat-file --batch-check", &checkErr}} {
		if err := p.c.Wait(); err != nil && ctx.Err() == nil {
			return nil, fmt.Errorf("sweep: git %s in %s: %w%s", p.name, repo, err, p.err.suffix())
		}
	}
	switch {
	case ctx.Err() != nil:
		return nil, ctx.Err()
	case readErr != nil:
		return nil, fmt.Errorf("sweep: listing blobs of %s: %w", repo, readErr)
	}
	return ids, nil
}

// listing is a range's blob ids, computed once however many engines ask for it: three engines
// at the same tips share one rev-list.
type listing struct {
	done chan struct{}
	ids  []oid
	err  error
}

// listings caches the listings of one source's scan by the range they were made for.
type listings struct {
	mu sync.Mutex
	m  map[string]*listing
}

// of starts (or joins) the listing of r in repo. The caller waits on done.
func (ls *listings) of(ctx context.Context, repo string, r core.Range) *listing {
	args, err := revArgs(r)
	l := &listing{done: make(chan struct{})}
	if err != nil {
		l.err = err
		close(l.done)
		return l
	}
	key := strings.Join(args, " ")
	ls.mu.Lock()
	if ls.m == nil {
		ls.m = map[string]*listing{}
	}
	if have := ls.m[key]; have != nil {
		ls.mu.Unlock()
		return have
	}
	ls.m[key] = l
	ls.mu.Unlock()
	go func() {
		defer close(l.done)
		defer func() {
			if p := recover(); p != nil {
				l.err = fmt.Errorf("sweep: panic while listing blobs: %s", safeText(fmt.Sprint(p)))
			}
		}()
		l.ids, l.err = blobIDs(ctx, "git", repo, args)
	}()
	return l
}
