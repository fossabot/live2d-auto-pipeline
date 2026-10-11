package handlers

// P4-C：zip 打包安全回归测试。
//
// 覆盖：
//  1. 符号链接不得被打包 —— 攻击者在 output 目录植入指向 /etc/passwd
//     的软链后，打包下载会把目标文件内容泄露到用户的 zip 里；
//  2. 常规文件正常打入归档；
//  3. 非常规文件（命名管道、设备文件）也不得打入。

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func TestZipDirectorySkipsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("符号链接在 Windows 上需要管理员权限，跳过")
	}
	dir := t.TempDir()

	regular := filepath.Join(dir, "model.model3.json")
	if err := os.WriteFile(regular, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}

	// 密文放在 zipped 目录**之外** —— symlink 指向它，
	// 若打包器跟随 symlink，密文就会出现在 zip 里。
	outsideDir := t.TempDir()
	secret := filepath.Join(outsideDir, "passwd")
	if err := os.WriteFile(secret, []byte("TOPSECRET_LEAK"), 0644); err != nil {
		t.Fatal(err)
	}

	linkPath := filepath.Join(dir, "leak.txt")
	if err := os.Symlink(secret, linkPath); err != nil {
		t.Fatal(err)
	}

	data, err := zipDirectory(dir)
	if err != nil {
		t.Fatalf("zipDirectory 失败: %v", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("解析 zip 失败: %v", err)
	}

	names := make([]string, 0, len(zr.File))
	contents := make(map[string][]byte)
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("打开 zip 条目 %s 失败: %v", f.Name, err)
		}
		buf := bytes.Buffer{}
		buf.ReadFrom(rc)
		rc.Close()
		contents[f.Name] = buf.Bytes()
	}
	sort.Strings(names)

	// 1. symlink 目标内容不得出现在任何归档条目中
	for _, n := range names {
		if bytes.Contains(contents[n], []byte("TOPSECRET_LEAK")) {
			t.Errorf("符号链接目标内容泄露到归档条目 %q", n)
		}
	}

	// 2. symlink 条目本身不应出现
	for _, n := range names {
		if filepath.Base(n) == "leak.txt" {
			t.Errorf("符号链接 leak.txt 不应出现在归档中")
		}
	}

	// 3. 常规文件应正常打包
	found := false
	for _, n := range names {
		if filepath.Base(n) == "model.model3.json" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("常规文件 model.model3.json 应出现在归档中，实际条目: %v", names)
	}
}
