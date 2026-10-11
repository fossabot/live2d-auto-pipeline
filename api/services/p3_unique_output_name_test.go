package services

// P3-M6 Go 侧配套：产物目录名必须抗并发碰撞。秒级时间戳在并发请求落
// 同一秒时会生成同名目录（layers_/psd_plan_/psd_import_/png_import_），
// 两个任务互相覆盖图层文件；crypto/rand 主路径 + 纳秒时间戳/计数器兜底
// 路径都必须保证唯一。

import (
	"bytes"
	"image"
	"image/png"
	"mime/multipart"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"live2d-api/config"
)

func TestP3UniqueOutputNameConcurrent(t *testing.T) {
	const goroutines = 64
	const per = 64

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := make(map[string]struct{}, goroutines*per)
	var badPrefix []string

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			local := make([]string, 0, per)
			for j := 0; j < per; j++ {
				local = append(local, uniqueOutputName("layers_"))
			}
			mu.Lock()
			defer mu.Unlock()
			for _, n := range local {
				if !strings.HasPrefix(n, "layers_") {
					badPrefix = append(badPrefix, n)
				}
				if _, dup := seen[n]; dup {
					t.Errorf("并发产物名碰撞: %q", n)
				}
				seen[n] = struct{}{}
			}
		}()
	}
	wg.Wait()

	if len(badPrefix) > 0 {
		t.Errorf("名称缺少可读前缀，示例: %q", badPrefix[0])
	}
}

// 熵源故障兜底路径不能退化为固定名：旧实现用 PID + 恒为 0 的 b[0]，
// 同一进程内每次调用都返回同名目录，等于把碰撞问题原样保留。
func TestP3FallbackOutputNameUnique(t *testing.T) {
	a := fallbackOutputName("layers_")
	b := fallbackOutputName("layers_")
	if a == b {
		t.Fatalf("兜底产物名碰撞: %q（纳秒时间戳+计数器必须参与命名）", a)
	}
	if !strings.HasPrefix(a, "layers_") || !strings.HasPrefix(b, "layers_") {
		t.Fatalf("兜底名缺少前缀: %q / %q", a, b)
	}
}

// 端到端回归：同一秒并发的两次 PNG 批量导入必须落在不同目录，且各自目录名
// 保留 png_import_ 前缀（旧秒级时间戳实现下两者共享目录、图层互相覆盖）。
func TestP3ImportPNGSetConcurrentDirs(t *testing.T) {
	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatalf("构造测试 PNG 失败: %v", err)
	}
	pngBytes := pngBuf.Bytes()

	mkHeader := func(t *testing.T) *multipart.FileHeader {
		t.Helper()
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, err := mw.CreateFormFile("file", "layer.png")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(pngBytes); err != nil {
			t.Fatal(err)
		}
		mw.Close()
		pr := multipart.NewReader(bytes.NewReader(body.Bytes()), mw.Boundary())
		form, err := pr.ReadForm(int64(len(pngBytes) + 4096))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = form.RemoveAll() })
		return form.File["file"][0]
	}

	cfg := &config.Config{Output: config.OutputConfig{BaseDir: t.TempDir()}}

	dir1, _, err1 := ImportPNGSet(cfg, []*multipart.FileHeader{mkHeader(t)})
	dir2, _, err2 := ImportPNGSet(cfg, []*multipart.FileHeader{mkHeader(t)})
	if err1 != nil || err2 != nil {
		t.Fatalf("并发导入失败: %v / %v", err1, err2)
	}
	if dir1 == dir2 {
		t.Fatalf("两个并发导入共享目录 %q，图层会互相覆盖", dir1)
	}
	for _, d := range []string{dir1, dir2} {
		if !strings.HasPrefix(filepath.Base(d), "png_import_") {
			t.Fatalf("目录名丢失可读前缀: %q", d)
		}
	}
}
