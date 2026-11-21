package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// cookieFile 是持久化到磁盘的 Cookie 记录格式。
// 只保留会话必需的字段，避免把浏览器元数据写进配置目录。
type cookieFile struct {
	Cookies []cookieRecord `json:"cookies"`
}

type cookieRecord struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Path    string `json:"path,omitempty"`
	Domain  string `json:"domain,omitempty"`
	Expires int64  `json:"expires,omitempty"`
	Secure  bool   `json:"secure,omitempty"`
}

// SaveCookies 把当前会话 Cookie 写入 path，权限 0600；path 为空时不做任何事。
func (c *Client) SaveCookies(path string) error {
	if path == "" {
		return nil
	}
	records := make([]cookieRecord, 0, len(c.Cookies()))
	for _, ck := range c.Cookies() {
		records = append(records, cookieRecord{
			Name:    ck.Name,
			Value:   ck.Value,
			Path:    ck.Path,
			Expires: ck.Expires.Unix(),
			Secure:  ck.Secure,
		})
	}
	payload, err := json.MarshalIndent(cookieFile{Cookies: records}, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 cookie: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建 cookie 目录: %w", err)
	}
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		return fmt.Errorf("写入 cookie: %w", err)
	}
	return nil
}

// LoadCookies 从 path 恢复会话 Cookie；文件不存在或 path 为空时返回 nil。
func (c *Client) LoadCookies(path string) error {
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("读取 cookie: %w", err)
	}
	parsed := cookieFile{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("解析 cookie: %w", err)
	}
	cookies := make([]*http.Cookie, 0, len(parsed.Cookies))
	for _, rec := range parsed.Cookies {
		cookies = append(cookies, &http.Cookie{Name: rec.Name, Value: rec.Value, Path: rec.Path, Secure: rec.Secure})
	}
	c.SetCookies(cookies)
	return nil
}
