package bench

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"os/exec"
	"slices"
	"testing"
	"time"
)

func TestMedian(t *testing.T) {
	for _, tc := range []struct {
		in   []float64
		want float64
	}{{[]float64{3}, 3}, {[]float64{5, 1, 3}, 3}, {[]float64{4, 1, 3, 2}, 2.5}} {
		in := append([]float64(nil), tc.in...)
		if got := median(tc.in); got != tc.want {
			t.Errorf("median(%v) = %v, want %v", in, got, tc.want)
		}
		if !slices.Equal(in, tc.in) {
			t.Errorf("median reordered its input: %v became %v", in, tc.in)
		}
	}
}

// busyChild holds memory and burns CPU for a moment, like a scanner on a repo.
const busyChild = `
import time
block = b"x" * (120 << 20)   # written to, so the pages are really resident
t = time.process_time()
while time.process_time() - t < 0.3:
    pass
print(len(block))
`

func TestMeasureSpeedSeesTheEnginesProcesses(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed, and it is the child this test measures")
	}
	res := MeasureSpeed(context.Background(), "busy", "1.0", "repo", 4, func(ctx context.Context) error {
		return exec.CommandContext(ctx, py, "-c", busyChild).Run()
	})
	if res.Error != "" || res.Runs != 4 || res.Engine != "busy" || res.Version != "1.0" || res.Repo != "repo" {
		t.Fatalf("%+v", res)
	}
	if res.ColdSeconds < 0.3 || res.WarmSeconds < 0.3 || res.MinSeconds > res.WarmSeconds || res.MaxSeconds < res.WarmSeconds {
		t.Errorf("wall times: cold %.2f warm %.2f min %.2f max %.2f", res.ColdSeconds, res.WarmSeconds, res.MinSeconds, res.MaxSeconds)
	}
	// the child spins for 0.3 s of CPU, plus start-up and the allocation
	if res.CPUSeconds < 0.25 || res.CPUSeconds > 1.5 {
		t.Errorf("CPU %.2f s for a child that burns 0.3 s", res.CPUSeconds)
	}
	// 120 MB of the child's memory is touched; the interpreter adds some
	if res.PeakRSSMB < 110 || res.PeakRSSMB > 1500 {
		t.Errorf("peak RSS %.0f MB for a child that holds 120 MB", res.PeakRSSMB)
	}
}

// With nothing running as a child the CPU is the sampler's own cost, which is taken back out.
func TestMeasureSpeedDoesNotChargeTheEngineForItsOwnSampling(t *testing.T) {
	res := MeasureSpeed(context.Background(), "idle", "", "repo", 2, func(context.Context) error {
		time.Sleep(300 * time.Millisecond)
		return nil
	})
	if res.Runs != 2 || res.PeakRSSMB != 0 {
		t.Errorf("an engine with no processes: %+v", res)
	}
	if res.CPUSeconds > 0.05 {
		t.Errorf("CPU %.3f s charged to a scan that started no process: the sampler's ps calls leaked into it", res.CPUSeconds)
	}
}

func TestMeasureSpeedStopsAtAnErrorAndKeepsWhatItHad(t *testing.T) {
	n := 0
	res := MeasureSpeed(context.Background(), "flaky", "", "repo", 5, func(context.Context) error {
		n++
		if n == 3 {
			return errors.New("boom")
		}
		return nil
	})
	if res.Error != "boom" || res.Runs != 2 || n != 3 {
		t.Errorf("%+v after %d calls", res, n)
	}
}

func makeZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	zw.Close()
	return buf.Bytes()
}

func makeTgz(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	tw.Write(body)
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func walk(data []byte) map[string]string {
	got := map[string]string{}
	left := int64(maxArchiveTotal)
	expandArchive(data, "x", 0, &left, func(name string, b []byte) { got[name] = string(b) })
	return got
}

func TestExpandArchiveOpensWhatTheFullScanOpens(t *testing.T) {
	zipped := makeZip(t, map[string][]byte{"a.env": []byte("A=1\n"), "dir/b.txt": []byte("B=2\n")})
	if got := walk(zipped); got["x!a.env"] != "A=1\n" || got["x!dir/b.txt"] != "B=2\n" || len(got) != 2 {
		t.Errorf("zip: %v", got)
	}
	if got := walk(makeTgz(t, ".env", []byte("C=3\n"))); got[`x!.env`] != "C=3\n" || len(got) != 1 {
		t.Errorf("tgz: %v", got)
	}
	var plain bytes.Buffer
	gz := gzip.NewWriter(&plain)
	gz.Write([]byte("D=4\n"))
	gz.Close()
	if got := walk(plain.Bytes()); got["x!"] != "D=4\n" || len(got) != 1 {
		t.Errorf("a bare gzip: %v", got)
	}
	// a zip holding a tgz: both levels are visited, and the leaf is named the way betterleaks names members
	nested := makeZip(t, map[string][]byte{"inner.tgz": makeTgz(t, ".env", []byte("E=5\n"))})
	got := walk(nested)
	if got["x!inner.tgz!.env"] != "E=5\n" || len(got) != 2 {
		t.Errorf("nested: %v", got)
	}
	// depth is capped: an archive four deep is not opened
	deep := []byte("F=6\n")
	for i := 0; i < 4; i++ {
		deep = makeZip(t, map[string][]byte{"n.zip": deep})
	}
	for name, b := range walk(deep) {
		if string(b) == "F=6\n" {
			t.Errorf("the leaf of a 4-deep archive was opened: %s", name)
		}
	}
	// damaged input is skipped, not a panic
	if len(walk([]byte("PK\x03\x04 not a zip at all"))) != 0 || len(walk([]byte{0x1f, 0x8b, 0, 0})) != 0 {
		t.Error("a damaged archive yielded members")
	}
	// the byte budget ends the walk
	left := int64(3)
	n := 0
	expandArchive(zipped, "x", 0, &left, func(string, []byte) { n++ })
	if n != 0 {
		t.Errorf("%d members visited past a budget of 3 bytes", n)
	}
}
