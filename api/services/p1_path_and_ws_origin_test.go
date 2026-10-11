package services

// P1 安全修复回归测试：
//  1. segment / psd-plan 源图路径必须限定在 Output.BaseDir 内（FF-16-S2 白名单落地）；
//  2. WebSocket 握手必须校验 Origin（无 Origin 的非浏览器客户端放行）。
//
// 独立成文以便审阅与单独回滚。

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"live2d-api/config"
)

func newP1TestBridge(t *testing.T) (*PythonBridge, string) {
	t.Helper()
	base := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Output.BaseDir = base
	// 不存在的解释器：归属校验通过后会快速失败在 exec.LookPath，不会真跑 Python。
	cfg.Python.PythonPath = "definitely-not-a-python-binary"
	return NewPythonBridge(cfg), base
}

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("建目录失败: %v", err)
	}
	if err := os.WriteFile(p, []byte("fake-png-bytes"), 0o644); err != nil {
		t.Fatalf("写文件失败: %v", err)
	}
}

// 攻击向量：输出根之外的绝对路径（文件存在与否都必须被归属校验拦下，
// 且必须先于 os.Stat —— 否则错误差异会变成文件存在性探测 oracle）。
func TestSegmentImage_RejectsPathOutsideBase(t *testing.T) {
	pb, _ := newP1TestBridge(t)

	existing := filepath.Join(t.TempDir(), "secret.png")
	writeFile(t, existing)
	if _, err := pb.SegmentImage(context.Background(), existing, "kmeans"); !errors.Is(err, ErrPathOutsideBase) {
		t.Fatalf("根外存在文件应被归属校验拒绝，实得 %v", err)
	}

	missing := filepath.Join(t.TempDir(), "nope.png")
	if _, err := pb.SegmentImage(context.Background(), missing, "kmeans"); !errors.Is(err, ErrPathOutsideBase) {
		t.Fatalf("根外不存在的路径也应被归属校验拒绝（避免存在性 oracle），实得 %v", err)
	}
}

func TestCreatePSDPlan_RejectsPathOutsideBase(t *testing.T) {
	pb, _ := newP1TestBridge(t)

	outside := filepath.Join(t.TempDir(), "secret.png")
	writeFile(t, outside)
	if _, err := pb.CreatePSDPlan(context.Background(), outside); !errors.Is(err, ErrPathOutsideBase) {
		t.Fatalf("PSD 规划应拒绝根外源图，实得 %v", err)
	}
}

// 负向保护：输出根内的合法图片必须通过归属校验（后续在假解释器处失败，
// 但错误绝不能是 ErrPathOutsideBase，否则正常业务被误伤）。
func TestSourceImageInsideBaseIsNotOverBlocked(t *testing.T) {
	pb, base := newP1TestBridge(t)
	inside := filepath.Join(base, "uploads", "src.png")
	writeFile(t, inside)

	if _, err := pb.SegmentImage(context.Background(), inside, "kmeans"); errors.Is(err, ErrPathOutsideBase) {
		t.Fatalf("输出根内上传图被误伤: %v", err)
	}
	if _, err := pb.CreatePSDPlan(context.Background(), inside); errors.Is(err, ErrPathOutsideBase) {
		t.Fatalf("输出根内上传图被 PSD 规划误伤: %v", err)
	}
}

// ---------- WebSocket Origin 白名单 ----------

func wsHandshakeStatus(t *testing.T, addr, origin string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	req := "GET /api/ws HTTP/1.1\r\n" +
		"Host: localhost:8080\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
	if origin != "" {
		req += "Origin: " + origin + "\r\n"
	}
	req += "\r\n"
	if _, err := fmt.Fprint(conn, req); err != nil {
		t.Fatalf("发送握手失败: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("读取握手响应失败: %v", err)
	}
	return line
}

func TestWSHandshakeOriginPolicy(t *testing.T) {
	hub := NewWSHubWithOrigins([]string{"http://localhost:3000"}, 8080)
	go hub.Run()
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleUpgrade))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// 跨站网页：握手必须在 hijack 前被 403 拒绝
	if line := wsHandshakeStatus(t, addr, "http://evil.example"); !strings.Contains(line, "403") {
		t.Errorf("恶意 Origin 应返回 403，实得 %q", line)
	}
	// 白名单工作台 / 服务自身同源：101 升级
	for _, origin := range []string{
		"http://localhost:3000",
		"http://127.0.0.1:3000",
		"http://localhost:8080",
	} {
		if line := wsHandshakeStatus(t, addr, origin); !strings.Contains(line, "101") {
			t.Errorf("白名单 Origin %s 应握手成功(101)，实得 %q", origin, line)
		}
	}
	// 非浏览器客户端（无 Origin，如本机程序/curl）：放行
	if line := wsHandshakeStatus(t, addr, ""); !strings.Contains(line, "101") {
		t.Errorf("无 Origin 的非浏览器客户端应放行，实得 %q", line)
	}
}

func TestWSHandshakeRejectsNonUpgrade(t *testing.T) {
	hub := NewWSHub()
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleUpgrade))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/api/ws")
	if err != nil {
		t.Fatalf("普通 GET 失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("非 Upgrade 请求应 400，实得 %d", resp.StatusCode)
	}
}

// wsDialAndHold 完成 WS 握手并保持连接打开（返回连接与首行状态）。
func wsDialAndHold(t *testing.T, addr string) (net.Conn, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	req := "GET /api/ws HTTP/1.1\r\n" +
		"Host: localhost:8080\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := fmt.Fprint(conn, req); err != nil {
		conn.Close()
		t.Fatalf("发送握手失败: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		conn.Close()
		t.Fatalf("读取握手响应失败: %v", err)
	}
	return conn, line
}

// M7：连接数上限必须在 hijack/101 之前以普通 HTTP 503 拒绝，且连接断开后
// 槽位立即释放，后续合法连接不受影响（攻击拦截 + 合法路径放行双向验证）。
func TestWSHandshakeConnectionCapRejectedBeforeUpgrade(t *testing.T) {
	hub := NewWSHubWithOrigins(nil, 8080)
	hub.SetMaxConns(1)
	go hub.Run()
	srv := httptest.NewServer(http.HandlerFunc(hub.HandleUpgrade))
	defer srv.Close()
	addr := strings.TrimPrefix(srv.URL, "http://")

	// 第一条合法连接占住唯一槽位（101 升级成功）
	first, line := wsDialAndHold(t, addr)
	if !strings.Contains(line, "101") {
		first.Close()
		t.Fatalf("首条合法连接应升级成功，实得 %q", line)
	}
	if hub.ActiveConns() != 1 {
		t.Fatalf("占槽计数应为 1，实得 %d", hub.ActiveConns())
	}

	// 第二条连接必须在握手阶段被 503 拒绝（拿不到 101）
	if status := wsHandshakeStatus(t, addr, ""); !strings.Contains(status, "503") {
		t.Errorf("超上限连接应在 hijack 前返回 503，实得 %q", status)
	}
	// 被拒连接不得占用槽位
	if hub.ActiveConns() != 1 {
		t.Errorf("拒绝的连接不应占槽，实得 %d", hub.ActiveConns())
	}

	// 第一条断开后槽位必须释放（readPump 读到 EOF 即退出）
	first.Close()
	deadline := time.Now().Add(3 * time.Second)
	for hub.ActiveConns() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if hub.ActiveConns() != 0 {
		t.Fatalf("断开后槽位未释放，仍有 %d 个连接", hub.ActiveConns())
	}

	// 释放后新的合法连接必须能正常升级
	third, line := wsDialAndHold(t, addr)
	defer third.Close()
	if !strings.Contains(line, "101") {
		t.Errorf("槽位释放后合法连接应能升级，实得 %q", line)
	}
}
