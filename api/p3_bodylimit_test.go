package main

// P3-M2：全局 10MB body 上限曾让 25MB 上传与 500MB PSD 导入必然失败。
// 上限必须按路径区分：默认 10MB（JSON），/api/upload 25MB，
// /api/import/psd 与 /api/import/pngs 500MB。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"live2d-api/config"
)

func TestRequestBodyLimitByPath(t *testing.T) {
	cfg := config.DefaultConfig()
	if cfg.Server.MaxRequestBodySize != 10<<20 {
		t.Fatalf("默认 JSON 上限应为 10MB，实得 %d", cfg.Server.MaxRequestBodySize)
	}
	cases := []struct {
		path string
		want int64
	}{
		{"/api/segment", 10 << 20},
		{"/api/upload", 25 << 20},
		{"/api/import/psd", 500 << 20},
		{"/api/import/pngs", 500 << 20},
	}
	for _, tc := range cases {
		if got := requestBodyLimit(cfg, tc.path); got != tc.want {
			t.Errorf("%s 上限 = %d, want %d", tc.path, got, tc.want)
		}
	}
}

func bodyLimitRouter(cfg *config.Config) *gin.Engine {
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(
			c.Writer, c.Request.Body, requestBodyLimit(cfg, c.Request.URL.Path),
		)
		c.Next()
	})
	r.POST("/api/import/psd", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})
	r.POST("/api/segment", func(c *gin.Context) {
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			c.Status(http.StatusRequestEntityTooLarge)
			return
		}
		c.Status(http.StatusOK)
	})
	return r
}

func TestBodyLimitAllowsLargePSDButStillCapsJSON(t *testing.T) {
	r := bodyLimitRouter(config.DefaultConfig())

	// 11MB 请求体打 PSD 导入：旧的全局 10MB 会误杀，新的路径上限必须放行
	big := strings.NewReader(strings.Repeat("x", 11<<20))
	req := httptest.NewRequest(http.MethodPost, "/api/import/psd", big)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("11MB PSD 应在 500MB 路径上限下放行，实得 %d", w.Code)
	}

	// 同样 11MB 打 JSON 端点仍必须被 10MB 默认上限拦住
	big2 := strings.NewReader(strings.Repeat("x", 11<<20))
	req2 := httptest.NewRequest(http.MethodPost, "/api/segment", big2)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("JSON 端点 11MB 应被默认 10MB 上限拒绝，实得 %d", w2.Code)
	}
}
