package services

// P4-E：PNG 批量导入两遍扫描的功能回归测试。
//
// 旧实现把全部文件一次性解码到内存（200 张 4K PNG 峰值 ~6.6GB）。
// 新实现改为两遍扫描：第一遍只读 header 拿尺寸，第二遍逐张解码→规范化→写盘。
// 本测试验证功能等价性：多个异尺寸 PNG 被正确导入并规范化到统一画布。

import (
	"bytes"
	"fmt"
	"image"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"live2d-api/config"
)

func TestP4ImportPNGSetTwoPassCorrectness(t *testing.T) {
	cfg := &config.Config{Output: config.OutputConfig{BaseDir: t.TempDir()}}

	sizes := []struct{ w, h int }{
		{32, 32},
		{64, 48},
		{48, 64},
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for i, s := range sizes {
		fw, err := mw.CreateFormFile("files", fmt.Sprintf("layer_%d.png", i))
		if err != nil {
			t.Fatal(err)
		}
		img := image.NewRGBA(image.Rect(0, 0, s.w, s.h))
		if err := png.Encode(fw, img); err != nil {
			t.Fatal(err)
		}
	}
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/import/pngs", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if err := req.ParseMultipartForm(10 << 20); err != nil {
		t.Fatal(err)
	}

	files := req.MultipartForm.File["files"]
	if len(files) != len(sizes) {
		t.Fatalf("解析 multipart 应得到 %d 个文件，实得 %d", len(sizes), len(files))
	}

	dir, layers, err := ImportPNGSet(cfg, files)
	if err != nil {
		t.Fatalf("ImportPNGSet 失败: %v", err)
	}

	if len(layers) != len(sizes) {
		t.Fatalf("应导入 %d 个图层，实得 %d", len(sizes), len(layers))
	}

	for i, layer := range layers {
		layerPath, _ := layer["path"].(string)
		if layerPath == "" {
			t.Fatalf("图层 %d 缺少 path", i)
		}
		if _, err := os.Stat(layerPath); err != nil {
			t.Fatalf("图层 %d 文件不存在: %v", i, err)
		}
		f, err := os.Open(layerPath)
		if err != nil {
			t.Fatal(err)
		}
		cfg2, _, err := image.DecodeConfig(f)
		f.Close()
		if err != nil {
			t.Fatalf("图层 %d 无法解码: %v", i, err)
		}
		// 全部图层应被规范化到最大画布尺寸（64×64）
		if cfg2.Width != 64 || cfg2.Height != 64 {
			t.Errorf("图层 %d 应为 64×64 画布，实为 %d×%d", i, cfg2.Width, cfg2.Height)
		}
	}

	if dir == "" {
		t.Fatal("导入目录路径不应为空")
	}
}
