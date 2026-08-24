package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Scanning a directory means running a frontend and then this core, as two processes with
// a Program IR document between them. That is not an implementation detail to be tidied
// away into one address space: the seam is the architecture (ADR-001), and a convenience
// wrapper that erased it would make it possible for a frontend to start reaching into
// core state. What this adds is the wrapper, not a shortcut past the boundary.

// frontend describes how to lower one language.
type frontend struct {
	lang       string
	extensions []string
	// argv is how to invoke it, with the source root and output path appended.
	argv func(home, root, out string) []string
}

func frontends() []frontend {
	return []frontend{
		{
			lang:       "typescript",
			extensions: []string{".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"},
			argv: func(home, root, out string) []string {
				return []string{
					"node", "--max-old-space-size=8192",
					filepath.Join(home, "frontends", "typescript", "src", "index.ts"),
					root, "--out", out,
				}
			},
		},
		{
			lang:       "python",
			extensions: []string{".py"},
			argv: func(home, root, out string) []string {
				return []string{
					"python3",
					filepath.Join(home, "frontends", "python", "src", "main.py"),
					root, "--out", out,
				}
			},
		},
	}
}

// findHome locates the tree holding the frontends: SAST_HOME if set, otherwise the
// nearest ancestor of the executable or the working directory that contains them.
func findHome() (string, error) {
	if h := os.Getenv("SAST_HOME"); h != "" {
		if ok, _ := hasFrontends(h); ok {
			return h, nil
		}
		return "", fmt.Errorf("SAST_HOME=%s does not contain frontends/", h)
	}

	var starts []string
	if exe, err := os.Executable(); err == nil {
		starts = append(starts, filepath.Dir(exe))
	}
	if wd, err := os.Getwd(); err == nil {
		starts = append(starts, wd)
	}

	for _, start := range starts {
		for dir := start; ; {
			if ok, _ := hasFrontends(dir); ok {
				return dir, nil
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", fmt.Errorf("cannot find the frontends; set SAST_HOME to the checkout root")
}

func hasFrontends(dir string) (bool, error) {
	_, err := os.Stat(filepath.Join(dir, "frontends", "typescript", "src", "index.ts"))
	return err == nil, err
}

// pickFrontend chooses a language by counting source files under the root.
//
// It reports what it counted rather than only what it chose. A polyglot repository gets
// scanned in the majority language and the rest is not analyzed at all, and an operator
// who is not told that will read a quiet report as a clean one — the same failure ADR-003
// exists to prevent, arriving one level earlier than the analysis.
func pickFrontend(root string, forced string) (frontend, map[string]int, error) {
	counts := map[string]int{}
	byExt := map[string]string{}
	for _, f := range frontends() {
		for _, e := range f.extensions {
			byExt[e] = f.lang
		}
	}

	skip := map[string]bool{"node_modules": true, ".git": true, "dist": true, "build": true, "out": true, "coverage": true, "vendor": true, ".venv": true, "__pycache__": true}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // an unreadable subtree is not a reason to abandon the scan
		}
		if info.IsDir() {
			if skip[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".d.ts") {
			return nil
		}
		if lang, ok := byExt[filepath.Ext(p)]; ok {
			counts[lang]++
		}
		return nil
	})
	if err != nil {
		return frontend{}, counts, fmt.Errorf("walk %s: %w", root, err)
	}

	best, bestN := "", 0
	for lang, n := range counts {
		if n > bestN {
			best, bestN = lang, n
		}
	}
	if forced != "" {
		best = forced
	}
	if best == "" {
		return frontend{}, counts, fmt.Errorf("no source files under %s that any frontend can lower", root)
	}
	for _, f := range frontends() {
		if f.lang == best {
			return f, counts, nil
		}
	}
	return frontend{}, counts, fmt.Errorf("no frontend for language %q", best)
}

// lower runs a frontend and returns the path of the IR it wrote.
func lower(home, root, forced string) (string, error) {
	f, counts, err := pickFrontend(root, forced)
	if err != nil {
		return "", err
	}

	out, err := os.CreateTemp("", "sast-ir-*.json")
	if err != nil {
		return "", fmt.Errorf("create IR file: %w", err)
	}
	out.Close()

	argv := f.argv(home, root, out.Name())
	fmt.Fprintf(os.Stderr, "sast: lowering %s with the %s frontend\n", root, f.lang)
	for lang, n := range counts {
		if lang != f.lang {
			fmt.Fprintf(os.Stderr, "sast: NOT analyzed: %d %s file(s) - rerun with --lang %s to cover them\n", n, lang, lang)
		}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(out.Name())
		return "", fmt.Errorf("%s frontend failed: %w", f.lang, err)
	}
	return out.Name(), nil
}
