package bench

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"

	"keyguard/internal/core"
)

// eachObject streams every object of a repo, packed or loose with deltas resolved, through
// git cat-file --batch-all-objects --batch, the way the full scan feeds the known matcher.
func eachObject(ctx context.Context, repo string, visit func(sha, kind string, data []byte)) error {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "cat-file", "--batch-all-objects", "--batch")
	cmd.Env = gitEnv()
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	rd := bufio.NewReaderSize(out, 1<<20)
	for {
		header, err := rd.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		f := strings.Fields(header)
		if len(f) != 3 {
			return fmt.Errorf("bench: cat-file header %q", header)
		}
		size, _ := strconv.Atoi(f[2])
		data := make([]byte, size+1) // the object and the LF that follows it
		if _, err := io.ReadFull(rd, data); err != nil {
			return err
		}
		visit(f[0], f[1], data[:size])
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("bench: git cat-file: %w", err)
	}
	return nil
}

// countLines is the number of lines in every blob of a repo: the denominator that turns false
// alerts into a rate per line.
func countLines(repo string) (int, error) {
	n := 0
	err := eachObject(context.Background(), repo, func(_, kind string, data []byte) {
		if kind == "blob" {
			n += bytes.Count(data, []byte("\n"))
		}
	})
	return n, err
}

// scanKnown runs a known-secret matcher over everything the full scan feeds it. Every object is
// read once: blobs, and the archives inside them opened as the full scan opens them, and commit
// and tag objects too, because a key pasted into a commit message lives there and in no blob.
// Ref names are matched last, since a branch name holds a value and belongs to no object.
func scanKnown(ctx context.Context, repo string, m core.KnownMatcher, tmpl core.Location) ([]core.Hit, error) {
	paths, err := blobPaths(ctx, repo)
	if err != nil {
		return nil, err
	}
	var hits []core.Hit
	hitsIn := func(kind, path string, data []byte, bodyFrom int) {
		for _, km := range m.Match(data) {
			loc := tmpl
			loc.Kind = kind
			loc.Path = path
			if kind == "blob" {
				loc.Kind = "repo"
			}
			loc.Line = 1 + bytes.Count(data[:min(km.Offset, len(data))], []byte("\n"))
			if bodyFrom > 0 && km.Offset >= bodyFrom {
				// count from the message, not from the object's tree/author header
				loc.Line = bytes.Count(data[bodyFrom:min(km.Offset, len(data))], []byte("\n")) + 1
			}
			hits = append(hits, core.Hit{
				Engine: "known", Rule: "known:" + km.Variant, Type: "known", FP: km.FP, Shape: km.Shape,
				Len: km.Len, Verified: core.Unverified, Known: km.EntryID + " " + km.Name, Loc: loc,
			})
		}
	}
	err = eachObject(ctx, repo, func(sha, kind string, data []byte) {
		body := 0
		if kind == "commit" || kind == "tag" {
			if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
				body = i + 2
			}
		}
		hitsIn(kind, paths[sha], data, body)
		if kind == "blob" {
			left := int64(maxArchiveTotal)
			expandArchive(data, paths[sha], 0, &left, func(name string, content []byte) {
				hitsIn("blob", name, content, 0)
			})
		}
	})
	if err != nil {
		return nil, err
	}
	refs, err := refNames(ctx, repo)
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		for _, km := range m.Match([]byte(ref)) {
			loc := tmpl
			loc.Kind = "ref"
			// the ref as the hit may show it: the value is in it, so the match is shortened
			end := min(len(ref), km.Offset+max(km.Len, 1))
			loc.Ref = ref[:km.Offset] + "«" + km.Shape + "»" + ref[end:]
			loc.Line = 1
			hits = append(hits, core.Hit{
				Engine: "known", Rule: "known:" + km.Variant, Type: "known", FP: km.FP, Shape: km.Shape,
				Len: km.Len, Verified: core.Unverified, Known: km.EntryID + " " + km.Name, Loc: loc,
			})
		}
	}
	return hits, nil
}

func refNames(ctx context.Context, repo string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "for-each-ref", "--format=%(refname)")
	cmd.Env = gitEnv()
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bench: git for-each-ref: %w", err)
	}
	return strings.Fields(string(b)), nil
}

// blobPaths maps blob ids to the first path they were seen at.
func blobPaths(ctx context.Context, repo string) (map[string]string, error) {
	cmd := exec.CommandContext(ctx, "git", "-C", repo, "rev-list", "--objects", "--all")
	cmd.Env = gitEnv()
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("bench: git rev-list --objects: %w", err)
	}
	paths := map[string]string{}
	for _, l := range strings.Split(string(b), "\n") {
		sha, p, ok := strings.Cut(l, " ")
		if ok && paths[sha] == "" {
			paths[sha] = p
		}
	}
	return paths, nil
}
