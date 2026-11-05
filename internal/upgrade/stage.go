package upgrade

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// ErrChecksum is returned when a downloaded file does not match the sha256 the project published
// for it, or when the project's file and GitHub's own digest of the asset disagree. Nothing is
// staged for a release that fails it.
var ErrChecksum = errors.New("checksum mismatch")

var (
	darwinArm64 = regexp.MustCompile(`(?i)darwin[_-](arm64|aarch64)`)
	// not the binary: signatures, certificates, bundles and reports that sit beside it
	sideFile = regexp.MustCompile(`(?i)\.(sig|pem|asc|crt|json|txt|sbom|spdx|intoto\.jsonl|bundle)$`)
	sumsFile = regexp.MustCompile(`(?i)(^|[_-])checksums?\.txt$`)
	sumLine  = regexp.MustCompile(`^([0-9a-fA-F]{64})\s+\*?(\S.*)$`)
)

// pickAssets finds the darwin/arm64 build and the checksums file of a release. Exactly one of
// each: two candidates would mean guessing which to trust.
func pickAssets(rel Release) (bin, sums Asset, err error) {
	var bins, sumss []Asset
	for _, a := range rel.Assets {
		switch {
		case sumsFile.MatchString(a.Name):
			sumss = append(sumss, a)
		case darwinArm64.MatchString(a.Name) && !sideFile.MatchString(a.Name):
			bins = append(bins, a)
		}
	}
	names := func(as []Asset) string {
		var n []string
		for _, a := range as {
			n = append(n, a.Name)
		}
		return strings.Join(n, ", ")
	}
	switch {
	case len(bins) == 0:
		return bin, sums, fmt.Errorf("upgrade: %s has no darwin/arm64 build: %w", rel.Tag, errNoAsset)
	case len(bins) > 1:
		return bin, sums, fmt.Errorf("upgrade: %s has several darwin/arm64 builds (%s); refusing to guess", rel.Tag, names(bins))
	case len(sumss) == 0:
		return bin, sums, fmt.Errorf("upgrade: %s publishes no checksums file, so nothing can vouch for %s: %w", rel.Tag, bins[0].Name, errNoAsset)
	case len(sumss) > 1:
		return bin, sums, fmt.Errorf("upgrade: %s has several checksums files (%s); refusing to guess", rel.Tag, names(sumss))
	}
	return bins[0], sumss[0], nil
}

// parseChecksums reads sha256sum-style lines: a hex digest, spaces, a file name.
func parseChecksums(text string) map[string]string {
	out := map[string]string{}
	for _, l := range strings.Split(text, "\n") {
		if m := sumLine.FindStringSubmatch(strings.TrimRight(l, "\r")); m != nil {
			out[path.Base(strings.TrimPrefix(m[2], "./"))] = strings.ToLower(m[1])
		}
	}
	return out
}

// download writes an asset to dst, which must not exist, and returns its sha256. The write is
// capped at limit bytes. A download is only ever from GitHub's own hosts or the API host the
// options name.
func (o *Options) download(ctx context.Context, a Asset, dst string, limit int64) (string, error) {
	if !o.hostOK(hostOf(a.URL)) {
		return "", fmt.Errorf("upgrade: asset %s is hosted on %s, which is not GitHub", a.Name, hostOf(a.URL))
	}
	resp, err := o.get(ctx, a.URL, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // never over an existing path or through a link
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("upgrade: %s is larger than the %d byte limit", a.Name, limit)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hostOK reports whether a download may come from host.
func (o *Options) hostOK(host string) bool {
	host = strings.ToLower(host)
	return host != "" && (host == hostOf(o.api()) || host == "github.com" || host == "api.github.com" || strings.HasSuffix(host, ".githubusercontent.com"))
}

// Staged is a release's engine, downloaded, checked and unpacked, and not installed anywhere.
type Staged struct {
	Dir         string // the staging directory, which the caller removes or moves when done
	Binary      string // <Dir>/<engine>-<version>, mode 0755
	SHA256      string // of the binary: the hash to pin
	Asset       string // the file downloaded
	AssetSHA256 string // of the download, which matched the project's checksums file
}

// Stage downloads the darwin/arm64 asset of a release and its checksums file into a new
// directory, verifies the asset's sha256 against the file and against GitHub's digest when the
// API gave one, and unpacks the engine into <engine>-<version>. It writes only inside that
// directory, and never touches the engine that is in use.
func (o *Options) Stage(ctx context.Context, src Source, rel Release, ver Version) (Staged, error) {
	bin, sums, err := pickAssets(rel)
	if err != nil {
		return Staged{}, err
	}
	dir, err := os.MkdirTemp(o.tempRoot(), "keyguard-upgrade-"+src.Name+"-")
	if err != nil {
		return Staged{}, err
	}
	st := Staged{Dir: dir, Asset: bin.Name}
	sumsPath := filepath.Join(dir, "checksums.txt")
	if _, err := o.download(ctx, sums, sumsPath, 1<<20); err != nil {
		return st, err
	}
	text, err := os.ReadFile(sumsPath)
	if err != nil {
		return st, err
	}
	want, ok := parseChecksums(string(text))[bin.Name]
	if !ok {
		return st, fmt.Errorf("upgrade: the checksums file of %s does not list %s: %w", rel.Tag, bin.Name, ErrChecksum)
	}
	if d, ok := strings.CutPrefix(bin.Digest, "sha256:"); ok && !strings.EqualFold(d, want) {
		return st, fmt.Errorf("upgrade: GitHub's digest of %s and the project's checksums file disagree: %w", bin.Name, ErrChecksum)
	}
	assetPath := filepath.Join(dir, bin.Name)
	got, err := o.download(ctx, bin, assetPath, o.maxDownload())
	if err != nil {
		return st, err
	}
	if got != want {
		return st, fmt.Errorf("upgrade: %s hashes to %s…, the checksums file says %s…: %w", bin.Name, got[:12], want[:12], ErrChecksum)
	}
	st.AssetSHA256 = got

	dst := filepath.Join(dir, src.Name+"-"+ver.String())
	switch n := strings.ToLower(bin.Name); {
	case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"):
		err = unpackTar(assetPath, src.Binary, dst, o.maxBinary())
	case strings.HasSuffix(n, ".zip"):
		err = unpackZip(assetPath, src.Binary, dst, o.maxBinary())
	default:
		err = os.Rename(assetPath, dst) // a bare binary: the download is the engine
	}
	if err != nil {
		return st, err
	}
	if err := os.Chmod(dst, 0o755); err != nil {
		return st, err
	}
	st.Binary = dst
	if st.SHA256, err = fileSHA256(dst); err != nil {
		return st, err
	}
	return st, nil
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeBinary copies r to dst, which must not exist.
func writeBinary(dst string, r io.Reader, limit int64) error {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("upgrade: the engine inside the archive is larger than %d bytes", limit)
	}
	return err
}

// unpackTar writes the one member whose base name is binary to dst. No other member is
// written and no member's own path is used: an archive cannot place a file anywhere.
func unpackTar(archive, binary, dst string, limit int64) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("upgrade: %s holds no file named %s", filepath.Base(archive), binary)
		}
		if err != nil {
			return err
		}
		if h.Typeflag == tar.TypeReg && path.Base(h.Name) == binary {
			return writeBinary(dst, tr, limit)
		}
	}
}

func unpackZip(archive, binary, dst string, limit int64) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Mode().IsRegular() && path.Base(f.Name) == binary {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return writeBinary(dst, rc, limit)
		}
	}
	return fmt.Errorf("upgrade: %s holds no file named %s", filepath.Base(archive), binary)
}
