package login

import (
	"os"
	"path/filepath"
	"testing"
)

// TestArchiveSessionFile 校验被踢时会话文件被改名留档而不是直接删掉。
func TestArchiveSessionFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	if err := os.WriteFile(path, []byte(`{"cookies":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	archiveSessionFile(path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("原文件应被改名移走")
	}
	matches, _ := filepath.Glob(path + ".kicked-*")
	if len(matches) != 1 {
		t.Fatalf("应有 1 份存档，实际 %d", len(matches))
	}
}

// TestPruneSessionArchives 校验只保留最近 keep 份存档。
func TestPruneSessionArchives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.json")
	for _, name := range []string{"session.json.kicked-20260101-000001", "session.json.kicked-20260101-000002", "session.json.kicked-20260101-000003", "session.json.kicked-20260101-000004"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pruneSessionArchives(path, 2)
	matches, _ := filepath.Glob(path + ".kicked-*")
	if len(matches) != 2 {
		t.Fatalf("应保留 2 份，实际 %d: %v", len(matches), matches)
	}
	if filepath.Base(matches[0]) != "session.json.kicked-20260101-000003" {
		t.Fatalf("应保留最新的两份，实际 %v", matches)
	}
}
