// Command floor times the least any scanner can take over a directory on this machine: walk it
// and read every regular file once, with nothing done to the bytes. scripts/perf/run.py runs it
// beside the engines and uses its wall time as F, the read floor of the S2 gate
// (docs/NATIVE-BASELINE.md).
//
//	go run ./scripts/perf/floor -dir CORPUS [-workers N]
//
// It prints one JSON object. Like the engines it skips symlinks and .git directories. One
// goroutine walks while the workers read, as a scanner's own pipeline does, so the wall time is
// the walk and the reads together.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	Dir     string  `json:"dir"`
	Workers int     `json:"workers"`
	Files   int64   `json:"files"`
	Bytes   int64   `json:"bytes"`
	WallS   float64 `json:"wall_s"`
	MBps    float64 `json:"mb_per_s"`
}

func main() {
	dir := flag.String("dir", "", "directory to read")
	workers := flag.Int("workers", runtime.NumCPU(), "reader goroutines")
	flag.Parse()
	if *dir == "" || *workers < 1 {
		fmt.Fprintln(os.Stderr, "usage: floor -dir CORPUS [-workers N]")
		os.Exit(2)
	}
	if fi, err := os.Stat(*dir); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "floor: %s is not a directory\n", *dir)
		os.Exit(2)
	}

	paths := make(chan string, 4096)
	start := time.Now()
	go func() {
		defer close(paths)
		// An unreadable entry is skipped, as a scanner skips it; the file count shows the loss.
		_ = filepath.WalkDir(*dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type().IsRegular() {
				paths <- p
			}
			return nil
		})
	}()

	var files, total atomic.Int64
	var wg sync.WaitGroup
	for range *workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var buf []byte // one buffer per worker, grown to the biggest file it meets
			for p := range paths {
				f, err := os.Open(p)
				if err != nil {
					continue
				}
				fi, err := f.Stat()
				if err != nil {
					f.Close()
					continue
				}
				n := int(fi.Size())
				if cap(buf) < n {
					buf = make([]byte, n+n/4)
				}
				_, err = io.ReadFull(f, buf[:n])
				f.Close()
				if err != nil && n > 0 {
					continue
				}
				files.Add(1)
				total.Add(int64(n))
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start).Seconds()

	res := result{Dir: filepath.Base(*dir), Workers: *workers, Files: files.Load(), Bytes: total.Load(), WallS: round3(wall)}
	if wall > 0 {
		res.MBps = round3(float64(res.Bytes) / 1e6 / wall)
	}
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, "floor:", err)
		os.Exit(1)
	}
}

func round3(x float64) float64 { return float64(int64(x*1000+0.5)) / 1000 }
