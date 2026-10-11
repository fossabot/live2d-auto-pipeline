package services

// P3-M2 配套：/api/import/pngs 单文件 ≤25MB，但 200 个文件的聚合体积
// 必须同样封顶（与 PSD 的 500MB 对齐），否则 multipart 信封可到数 GB。

import (
	"mime/multipart"
	"strings"
	"testing"

	"live2d-api/config"
)

func TestP3ImportPNGSetAggregateCap(t *testing.T) {
	cfg := &config.Config{Output: config.OutputConfig{BaseDir: t.TempDir()}}
	// 每个文件都在 25MB 单文件上限内（25MB），但 21 个合计 525MB
	files := make([]*multipart.FileHeader, 0, 21)
	for i := 0; i < 21; i++ {
		files = append(files, &multipart.FileHeader{Filename: "a.png", Size: 25 << 20})
	}
	_, _, err := ImportPNGSet(cfg, files)
	if err == nil {
		t.Fatal("聚合体积超 500MB 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "总量") && !strings.Contains(err.Error(), "累计") {
		t.Fatalf("错误应指向批量总量限制，实得: %v", err)
	}
}
