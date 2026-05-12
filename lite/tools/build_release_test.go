package tools_test

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildReleasePackagesLicenseAndSecurityFiles(t *testing.T) {
	dist := t.TempDir()
	cmd := exec.Command("bash", "build-release.sh")
	cmd.Env = append(os.Environ(),
		"DIST="+dist,
		"VERSION=v0.0.0-test",
		"LITE_RELEASE_TARGETS=linux/amd64",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build-release.sh failed: %v\n%s", err, output)
	}

	archive := filepath.Join(dist, "cloudrec-lite_v0.0.0-test_linux_amd64.tar.gz")
	entries := tarEntries(t, archive)
	for _, want := range []string{
		"cloudrec-lite_v0.0.0-test_linux_amd64/LICENSE",
		"cloudrec-lite_v0.0.0-test_linux_amd64/README.md",
		"cloudrec-lite_v0.0.0-test_linux_amd64/SECURITY.md",
		"cloudrec-lite_v0.0.0-test_linux_amd64/rules/",
	} {
		if !hasTarEntry(entries, want) {
			t.Fatalf("release archive missing %q; entries=%v", want, entries)
		}
	}
}

func tarEntries(t *testing.T, archive string) []string {
	t.Helper()

	file, err := os.Open(archive)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer file.Close()

	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open gzip stream: %v", err)
	}
	defer gzipReader.Close()

	var entries []string
	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			t.Fatalf("read tar entry: %v", err)
		}
		entries = append(entries, header.Name)
	}
	return entries
}

func hasTarEntry(entries []string, want string) bool {
	for _, entry := range entries {
		if entry == want || strings.HasPrefix(entry, want) {
			return true
		}
	}
	return false
}
