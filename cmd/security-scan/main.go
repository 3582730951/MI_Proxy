package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type finding struct {
	file    string
	line    int
	pattern string
}

var checks = []struct {
	name string
	re   *regexp.Regexp
}{
	{name: "private-key-material", re: regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |)?PRIVATE KEY-----`)},
	{name: "aws-access-key", re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{name: "weak-password-assignment", re: regexp.MustCompile(`(?i)\b(password|passwd)\s*=\s*["'][^"']{1,32}["']`)},
	{name: "weak-password-yaml", re: regexp.MustCompile(`(?i)\b(password|passwd|postgres_password)\s*:\s*["']?[A-Za-z0-9_.@-]{1,32}["']?\s*$`)},
	{name: "shell-string-command", re: regexp.MustCompile(`exec\.Command\((?:"sh"|"bash"|"cmd"|"powershell"),\s*(?:"-c"|"/c")`)},
	{name: "raw-command-execution", re: regexp.MustCompile(`\bexec\.Command(Context)?\(`)},
	{name: "curl-pipe-bash", re: regexp.MustCompile(`(?i)curl\s+[^|]+\|\s*(bash|sh)`)},
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var findings []finding
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "dist" || base == "node_modules" || base == ".next" {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanFile(path) {
			return nil
		}
		fileFindings, err := scan(path)
		if err != nil {
			return err
		}
		findings = append(findings, fileFindings...)
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "security scan failed: %v\n", err)
		os.Exit(2)
	}
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Printf("%s:%d %s\n", f.file, f.line, f.pattern)
		}
		os.Exit(1)
	}
	fmt.Println("security scan passed: no blocking local findings")
}

func scan(path string) ([]finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var findings []finding
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if isPolicyOnly(path, line) {
			continue
		}
		if isAllowlistedCommandExecutor(path, line) {
			continue
		}
		for _, check := range checks {
			if check.re.MatchString(line) {
				findings = append(findings, finding{file: path, line: lineNo, pattern: check.name})
			}
		}
	}
	return findings, scanner.Err()
}

func scanFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".md", ".html", ".css", ".js", ".json", ".yaml", ".yml", ".ps1", ".sh", ".txt":
		return true
	default:
		return false
	}
}

func isPolicyOnly(path, line string) bool {
	normalized := filepath.ToSlash(path)
	if normalized == ".semgrep.yml" {
		return true
	}
	return strings.HasPrefix(normalized, "docs/") && strings.Contains(line, "curl | bash")
}

func isAllowlistedCommandExecutor(path, line string) bool {
	normalized := filepath.ToSlash(path)
	return strings.HasSuffix(normalized, "internal/safeexec/safeexec.go") && strings.Contains(line, "exec.CommandContext")
}
