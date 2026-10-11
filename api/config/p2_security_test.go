package config

// P2-1：默认配置必须只监听本机回环。若有人把默认值改回 0.0.0.0，
// 桌面形态会在局域网无鉴权暴露，此用例直接失败。

import "testing"

func TestDefaultConfigBindsLoopbackOnly(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Server.Host != "127.0.0.1" {
		t.Fatalf("默认监听地址必须是 127.0.0.1（仅本机），实得 %q", cfg.Server.Host)
	}
}
