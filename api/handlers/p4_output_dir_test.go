package handlers

// P4-D：/output/ 目录请求不得返回目录列举。
//
// gin 的 c.File 对目录调用 http.ServeFile，后者默认返回 HTML 目录列举，
// 泄露 output 下全部产物清单（生成的图片、分层目录、导出模型等）。
// 面捕/预览只需具体文件，目录请求一律按「文件不存在」处理。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"live2d-api/config"
	"live2d-api/models"
)

func TestServeOutputRejectsDirectoryListing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	baseDir := t.TempDir()
	subDir := filepath.Join(baseDir, "layers_abc")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	pngPath := filepath.Join(subDir, "hair.png")
	if err := os.WriteFile(pngPath, []byte("\x89PNG\r\n\x1a\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Output: config.OutputConfig{BaseDir: baseDir}}
	h := &Handler{cfg: cfg}

	r := gin.New()
	r.GET("/output/*filepath", h.ServeOutput)

	// 1. 请求目录路径 → 不得返回 200 或 HTML 列举
	req := httptest.NewRequest(http.MethodGet, "/output/layers_abc/", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusOK {
		t.Errorf("目录请求不应返回 200（会泄露目录列举），实得 %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "Index of") || strings.Contains(body, "Directory listing") {
		t.Errorf("响应体包含 HTML 目录列举:\n%s", truncate(body, 300))
	}

	// 2. 请求根 output 目录 → 同样不得列举
	req2 := httptest.NewRequest(http.MethodGet, "/output/", nil)
	req2.Host = "127.0.0.1"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code == http.StatusOK &&
		(strings.Contains(w2.Body.String(), "Index of") || strings.Contains(w2.Body.String(), "Directory listing")) {
		t.Errorf("根目录请求返回了 HTML 目录列举")
	}

	// 3. 具体文件路径仍正常返回
	req3 := httptest.NewRequest(http.MethodGet, "/output/layers_abc/hair.png", nil)
	req3.Host = "127.0.0.1"
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		var resp models.Response
		_ = json.Unmarshal(w3.Body.Bytes(), &resp)
		t.Errorf("具体文件请求应返回 200，实得 %d: %s", w3.Code, resp.Error)
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
