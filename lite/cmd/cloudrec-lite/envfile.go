package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
)

var allowedEnvFileKeys = map[string]struct{}{
	"ALIBABA_CLOUD_ACCESS_KEY_ID":     {},
	"ALIBABA_CLOUD_ACCESS_KEY_SECRET": {},
	"ALIBABA_CLOUD_SECURITY_TOKEN":    {},
	"ALIBABA_CLOUD_REGION":            {},
	"ALIBABA_CLOUD_REGION_ID":         {},
}

func loadEnvFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}

	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open env file %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		key, value, ok, err := parseEnvLine(scanner.Text())
		if err != nil {
			return fmt.Errorf("parse env file %q line %d: %w", path, lineNumber, err)
		}
		if !ok {
			continue
		}
		if _, allowed := allowedEnvFileKeys[key]; !allowed {
			continue
		}
		if existing, exists := os.LookupEnv(key); exists && strings.TrimSpace(existing) != "" {
			continue
		}
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("set env %s from %q: %w", key, path, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read env file %q: %w", path, err)
	}
	return nil
}

func parseEnvLine(line string) (string, string, bool, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	line = strings.TrimPrefix(line, "export ")

	key, value, found := strings.Cut(line, "=")
	if !found {
		return "", "", false, errors.New("expected KEY=VALUE")
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return "", "", false, errors.New("empty key")
	}
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	return key, value, true, nil
}
