package main

// P2 安全修复回归测试：
//  1. 监听地址默认回环 + 环境变量覆盖优先级（LIVE2D_API_HOST > GO_API_HOST）；
//  2. Host 头白名单（DNS rebinding 防御）的归一化、集合构建与中间件拦截。
//
// 独立成文以便审阅与单独回滚。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestHostFromEnvPriority(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{"未设置", map[string]string{}, ""},
		{"仅兼容变量", map[string]string{"GO_API_HOST": "0.0.0.0"}, "0.0.0.0"},
		{"主变量优先", map[string]string{
			"GO_API_HOST": "0.0.0.0", "LIVE2D_API_HOST": "127.0.0.1",
		}, "127.0.0.1"},
		{"空白被忽略", map[string]string{"LIVE2D_API_HOST": "   "}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			if got := hostFromEnv(getenv); got != tc.want {
				t.Fatalf("hostFromEnv = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost", " 127.0.0.1 "}
	for _, h := range loopback {
		if !isLoopbackHost(h) {
			t.Errorf("%q 应判定为回环", h)
		}
	}
	external := []string{"0.0.0.0", "::", "192.168.1.10", ""}
	for _, h := range external {
		if isLoopbackHost(h) {
			t.Errorf("%q 不应判定为回环（空串的 :port 会绑所有接口）", h)
		}
	}
}

func TestCanonicalHostname(t *testing.T) {
	cases := map[string]string{
		"localhost:8080":   "localhost",
		"LOCALHOST:8080":   "localhost",
		"127.0.0.1:8080":   "127.0.0.1",
		"[::1]:8080":       "::1",
		"app.example.com.": "app.example.com",
		"app.example.com":  "app.example.com",
		"":                 "",
	}
	for in, want := range cases {
		if got := canonicalHostname(in); got != want {
			t.Errorf("canonicalHostname(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildAllowedHosts(t *testing.T) {
	set := buildAllowedHosts(
		[]string{"http://localhost:3000", "https://app.example.com:8443", "*"},
		"192.168.1.20, ,*",
	)
	for _, h := range []string{"localhost", "127.0.0.1", "::1", "app.example.com", "192.168.1.20"} {
		if _, ok := set[h]; !ok {
			t.Errorf("白名单应包含 %q", h)
		}
	}
	for _, h := range []string{"evil.example", "*", ""} {
		if _, ok := set[h]; ok {
			t.Errorf("白名单不应包含 %q", h)
		}
	}
}

func TestAllowedHostMiddleware(t *testing.T) {
	r := gin.New()
	r.Use(allowedHostMiddleware(buildAllowedHosts(
		[]string{"http://localhost:3000", "https://app.example.com"}, "",
	)))
	r.GET("/api/health", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	allowed := []string{
		"localhost:8080",
		"127.0.0.1:8080",
		"[::1]:8080",
		"app.example.com",
	}
	for _, host := range allowed {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		req.Host = host
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Host %q 应放行，实得 %d", host, w.Code)
		}
	}

	// DNS rebinding 主攻击向量：攻击者域名（即使解析到 127.0.0.1）必须 400
	for _, host := range []string{"evil.example", "evil.example:8080", ""} {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		req.Host = host
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("Host %q 应被 400 拒绝，实得 %d", host, w.Code)
		}
	}
}
