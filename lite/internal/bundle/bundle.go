package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	bundledrules "github.com/antgroup/CloudRec/lite/rules"
	bundledsamples "github.com/antgroup/CloudRec/lite/samples"
)

const (
	defaultProvider = "alicloud"
	appDir          = "cloudrec-lite"
)

// ResolveRulesDir returns a usable rule directory. If no local rules directory
// exists for the default path, the embedded rule pack is materialized into the
// user's cache directory and used instead.
func ResolveRulesDir(path string, provider string, preferProvider bool) (string, error) {
	provider = normalizeProvider(provider)
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		if preferProvider {
			return EnsureProviderRulesDir(provider)
		}
		return EnsureRulesRoot()
	}
	if info, err := os.Stat(candidate); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("rules path %q is not a directory", candidate)
		}
		return candidate, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat rules directory %q: %w", candidate, err)
	}

	switch cleanRulePath(candidate) {
	case "rules":
		if preferProvider {
			return EnsureProviderRulesDir(provider)
		}
		return EnsureRulesRoot()
	case "rules/" + provider:
		return EnsureProviderRulesDir(provider)
	}
	return "", fmt.Errorf("rules directory %q does not exist; pass --rules to a valid rule pack directory", candidate)
}

func EnsureRulesRoot() (string, error) {
	return ensureEmbeddedFS("rules", bundledrules.FS)
}

func EnsureProviderRulesDir(provider string) (string, error) {
	provider = normalizeProvider(provider)
	root, err := EnsureRulesRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, provider)
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("bundled rules for provider %q are unavailable: %w", provider, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("bundled rules for provider %q are not a directory", provider)
	}
	return dir, nil
}

func ResolveSamplesDir(path string, provider string) (string, error) {
	provider = normalizeProvider(provider)
	candidate := strings.TrimSpace(path)
	if candidate == "" {
		return EnsureProviderSamplesDir(provider)
	}
	if info, err := os.Stat(candidate); err == nil {
		if !info.IsDir() {
			return "", fmt.Errorf("samples path %q is not a directory", candidate)
		}
		return candidate, nil
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat samples directory %q: %w", candidate, err)
	}

	if cleanRulePath(candidate) == "samples/"+provider {
		return EnsureProviderSamplesDir(provider)
	}
	return "", fmt.Errorf("samples directory %q does not exist; pass --samples to a valid sample directory", candidate)
}

func EnsureProviderSamplesDir(provider string) (string, error) {
	provider = normalizeProvider(provider)
	root, err := ensureEmbeddedFS("samples", bundledsamples.FS)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, provider)
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("bundled samples for provider %q are unavailable: %w", provider, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("bundled samples for provider %q are not a directory", provider)
	}
	return dir, nil
}

func ensureEmbeddedFS(kind string, source fs.FS) (string, error) {
	hash, err := hashFS(source)
	if err != nil {
		return "", err
	}
	root, err := cacheRoot()
	if err != nil {
		return "", err
	}
	target := filepath.Join(root, "bundled", kind+"-"+hash)
	if err := extractFS(source, target); err != nil {
		return "", fmt.Errorf("extract bundled %s: %w", kind, err)
	}
	return target, nil
}

func cacheRoot() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		dir = os.TempDir()
	}
	root := filepath.Join(dir, appDir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return "", fmt.Errorf("create cache directory %q: %w", root, err)
	}
	return root, nil
}

func hashFS(source fs.FS) (string, error) {
	var files []string
	if err := fs.WalkDir(source, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		files = append(files, path)
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(files)

	sum := sha256.New()
	for _, path := range files {
		content, err := fs.ReadFile(source, path)
		if err != nil {
			return "", err
		}
		_, _ = sum.Write([]byte(path))
		_, _ = sum.Write([]byte{0})
		_, _ = sum.Write(content)
		_, _ = sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil))[:12], nil
}

func extractFS(source fs.FS, target string) error {
	return fs.WalkDir(source, ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == "." {
			return os.MkdirAll(target, 0o700)
		}
		dst := filepath.Join(target, filepath.FromSlash(path))
		if entry.IsDir() {
			return os.MkdirAll(dst, 0o755)
		}
		content, err := fs.ReadFile(source, path)
		if err != nil {
			return err
		}
		if existing, err := os.ReadFile(dst); err == nil && string(existing) == string(content) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, content, 0o644)
	})
}

func cleanRulePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func normalizeProvider(provider string) string {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return defaultProvider
	}
	return provider
}
