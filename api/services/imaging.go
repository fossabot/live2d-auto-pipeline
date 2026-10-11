package services

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"image"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// 本包所有图像处理均基于 Go 标准库（image/png、image/jpeg、image/draw），
// 不引入外部图像依赖，也不执行任何外部进程。
//
// 注意：标准库不解码 webp/bmp；图层导入因此仅接受 png/jpg/jpeg。

// decodeImageFile 按真实格式解码图片文件（png/jpeg）。
func decodeImageFile(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// decodeImageReader 按真实格式解码图片流（png/jpeg）。
func decodeImageReader(r io.Reader) (image.Image, error) {
	img, _, err := image.Decode(r)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// rejectOversizedImageConfig 只解析文件头（不解码像素、不按解压后尺寸
// 分配内存）就校验画布边界。标准库 image/png 没有像素总量保护，一张 ≤25MB
// 的 PNG 可声明数万边长（解压后数十 GB），必须在完整解码前拒绝，防 OOM。
func rejectOversizedImageConfig(r io.Reader) error {
	cfg, _, err := image.DecodeConfig(r)
	if err != nil {
		return err
	}
	if cfg.Width <= 0 || cfg.Height <= 0 {
		return fmt.Errorf("图片尺寸非法（%dx%d）", cfg.Width, cfg.Height)
	}
	if cfg.Width > maxImageDimension || cfg.Height > maxImageDimension {
		return fmt.Errorf(
			"图片尺寸 %dx%d 超出像素上限（单边最大 %d），疑似解压炸弹",
			cfg.Width, cfg.Height, maxImageDimension,
		)
	}
	return nil
}

// uniqueNameSeq 仅在 crypto/rand 失败的兜底路径上使用：单调计数器保证
// 同一纳秒内的并发调用也不会产出同名目录。
var uniqueNameSeq atomic.Uint64

// fallbackOutputName 是熵源故障时的兜底命名：纳秒时间戳 + 进程内单调序号。
// 绝不能退化成「PID + 固定字节」这种进程内恒定值——那样每次调用都同名，
// 碰撞防护形同虚设。
func fallbackOutputName(prefix string) string {
	return fmt.Sprintf("%s%d-%08x", prefix, time.Now().UnixNano(), uniqueNameSeq.Add(1))
}

// uniqueOutputName 生成「前缀 + 12 位随机 hex」的产物名，如 layers_1a2b3c4d5e6f。
//
// 秒级时间戳在并发请求落同一秒时会生成同名目录：两个分层/导入任务互相覆盖
// 图层文件、共享 PSD 产物（与 Python 侧 M6 同类问题）。crypto/rand 无需
// 引入依赖，碰撞概率可忽略；命名仍保留可读前缀，不影响 layers_* 等 glob。
func uniqueOutputName(prefix string) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// rand 失败极罕见（等于系统熵源故障）；用纳秒时间戳 + 单调计数器
		// 保证进程内唯一，且名称形态（前缀 + 十六进制串）与随机路径一致。
		return fallbackOutputName(prefix)
	}
	return prefix + hex.EncodeToString(b[:])
}

// NormalizeToCanvas 把 src 绘制到 maxW×maxH 的透明 RGBA 画布上
// （左上对齐），并写出为 PNG。Live2D 的所有网格共享同一张画布，
// 图层集必须在进入构建器之前完成这一规范化。
func NormalizeToCanvas(src image.Image, maxW, maxH int, destPath string) error {
	if src.Bounds().Dx() > maxW || src.Bounds().Dy() > maxH {
		return fmt.Errorf("图层尺寸 %s 超出画布 %dx%d", src.Bounds().Size(), maxW, maxH)
	}
	canvas := image.NewRGBA(image.Rect(0, 0, maxW, maxH))
	draw.Draw(canvas, canvas.Bounds(), src, src.Bounds().Min, draw.Over)

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()
	if err := png.Encode(out, canvas); err != nil {
		return err
	}
	return nil
}

// 保留 jpeg 解码注册（图层导入允许 jpg/jpeg 源），避免编译器报未使用。
var _ = jpeg.Decode
