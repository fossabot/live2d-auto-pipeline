package main

// P4-A：桌面端面捕（MediaPipe FaceLandmarker WASM）所需的安全头回归测试。
//
// 问题回顾：此前 CSP 为 default-src 'self'，阻止了：
//   - WASM 运行时（需要 unsafe-eval）；
//   - CDN 回退（jsdelivr / googleapis，当本地 vendor 缺失时面捕不应全功能失效）；
//   - blob:/data: 图片与摄像头流（getUserMedia + createObjectURL 产物）。
// Permissions-Policy camera=() 则直接禁用了摄像头访问。
//
// 本测试验证修复后的安全头满足面捕最低需求，同时不放松 frame-ancestors 等
// 防嵌入约束。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSecurityHeadersForFaceCapture(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(securityHeadersMiddleware())
	r.GET("/probe", func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	csp := w.Header().Get("Content-Security-Policy")

	checks := []struct {
		name, header, want string
	}{
		{"WASM 运行时需要 unsafe-eval", csp, "'unsafe-eval'"},
		{"MediaPipe WASM CDN 回退", csp, "cdn.jsdelivr.net"},
		{"模型 CDN 回退", csp, "storage.googleapis.com"},
		{"摄像头流需要 media-src blob:", csp, "blob:"},
		{"图片预览需要 img-src blob:/data:", csp, "data:"},
	}
	for _, c := range checks {
		if !strings.Contains(c.header, c.want) {
			t.Errorf("%s: CSP 缺少 %q\n  实际 CSP: %s", c.name, c.want, csp)
		}
	}

	pp := w.Header().Get("Permissions-Policy")
	if !strings.Contains(pp, "camera=(self)") {
		t.Errorf("Permissions-Policy 必须允许 camera=(self)（面捕需要）\n  实际: %s", pp)
	}
	if strings.Contains(pp, "camera=()") {
		t.Errorf("Permissions-Policy 不得完全禁用 camera\n  实际: %s", pp)
	}

	if strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("frame-ancestors 不得放宽为 'self'（防嵌入必须保持 none）\n  CSP: %s", csp)
	}
	if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options 应为 nosniff，实得 %q", got)
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options 应为 DENY，实得 %q", got)
	}
}
