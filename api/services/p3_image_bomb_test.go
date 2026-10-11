package services

// P3-M5：解压炸弹防护。Go 标准库 image/png 无像素总量保护，必须在完整
// 解码（按解压后像素分配内存）之前只解析文件头拒绝超大画布。

import (
	"bytes"
	"hash/crc32"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"strings"
	"testing"

	"live2d-api/config"
)

// craftPNGWithHeader 构造一个只有 PNG 签名 + IHDR（声称 w×h）的字节串，
// 不含图像数据；DecodeConfig 只读 IHDR，完整解码必然失败——正好验证
// 防护在"分配任何像素内存之前"就拦截。
func craftPNGWithHeader(t *testing.T, w, h uint32) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := bytes.NewBuffer(nil)
	ihdr.Write([]byte{byte(w >> 24), byte(w >> 16), byte(w >> 8), byte(w)})
	ihdr.Write([]byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h)})
	ihdr.WriteString("\x08\x06\x00\x00\x00") // 8bit RGBA
	chunk := append([]byte("IHDR"), ihdr.Bytes()...)
	buf.Write([]byte{0, 0, 0, 13})
	buf.Write(chunk)
	crc := crc32.ChecksumIEEE(chunk)
	buf.Write([]byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})
	return buf.Bytes()
}

func fileHeaderFromBytes(t *testing.T, fieldname, filename string, data []byte) *multipart.FileHeader {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile(fieldname, filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	mw.Close()
	pr := multipart.NewReader(bytes.NewReader(body.Bytes()), mw.Boundary())
	form, err := pr.ReadForm(int64(len(body.Bytes()) + 1024))
	if err != nil {
		t.Fatal(err)
	}
	fhs := form.File[fieldname]
	if len(fhs) != 1 {
		t.Fatalf("期望 1 个上传文件，实得 %d", len(fhs))
	}
	return fhs[0]
}

func TestP3OversizedPNGHeaderRejectedBeforeDecode(t *testing.T) {
	bomb := craftPNGWithHeader(t, 30000, 30000)
	if err := rejectOversizedImageConfig(bytes.NewReader(bomb)); err == nil {
		t.Fatal("30000x30000 的 PNG 头必须在解码前被拒绝")
	}
	// 正常小图的头必须放行
	var small bytes.Buffer
	if err := png.Encode(&small, image.NewRGBA(image.Rect(0, 0, 64, 64))); err != nil {
		t.Fatal(err)
	}
	if err := rejectOversizedImageConfig(bytes.NewReader(small.Bytes())); err != nil {
		t.Fatalf("64x64 正常图片不应被拒: %v", err)
	}
	// 边界：4096 恰好允许，4097 拒绝
	if err := rejectOversizedImageConfig(bytes.NewReader(craftPNGWithHeader(t, 4096, 4096))); err != nil {
		t.Fatalf("4096x4096 在业务上限内应放行: %v", err)
	}
	if err := rejectOversizedImageConfig(bytes.NewReader(craftPNGWithHeader(t, 4097, 4096))); err == nil {
		t.Fatal("4097 宽必须被拒绝")
	}
}

func TestP3ImportPNGSetRejectsBombWithoutHugeAllocation(t *testing.T) {
	cfg := &config.Config{Output: config.OutputConfig{BaseDir: t.TempDir()}}
	bomb := craftPNGWithHeader(t, 40000, 40000)
	fh := fileHeaderFromBytes(t, "files", "bomb.png", bomb)

	_, _, err := ImportPNGSet(cfg, []*multipart.FileHeader{fh})
	if err == nil {
		t.Fatal("超大像素 PNG 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "尺寸") && !strings.Contains(err.Error(), "像素") {
		t.Fatalf("错误应指向尺寸/像素限制，实得: %v", err)
	}
}

// 编译期保证 RGBA 被使用（防止 import 误删）
var _ color.Color = color.RGBA{}
