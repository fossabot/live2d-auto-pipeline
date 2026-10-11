package handlers

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// zipDirectory packs every regular file under dir into an in-memory zip.
// Paths inside the archive are relative to dir (the directory's base name
// is used as the top-level folder for easy extraction).
//
// 安全：跳过符号链接与非常规文件 —— os.Open 会跟随 symlink 打开目标，
// 攻击者在 output 目录植入指向 /etc/passwd 的软链后，打包下载会泄露目标
// 内容。只打包 info.Mode().IsRegular() 为 true 的条目。
func zipDirectory(dir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	root := filepath.Clean(dir)
	base := filepath.Base(root)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// 跳过符号链接、设备文件、命名管道等非常规文件
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Defensive: never write absolute or traversing entries.
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "../") || rel == ".." {
			return nil
		}
		arcName := base + "/" + rel
		w, err := zw.Create(arcName)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		// 显式关闭而非 defer：walk 可能遍历数千文件，defer 会把全部 fd
		// 累积到函数返回前才释放，大目录会触发 "too many open files"。
		n, copyErr := io.Copy(w, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return fmt.Errorf("打包 %s 不完整: 写入 %d / 期望 %d 字节", path, n, info.Size())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
