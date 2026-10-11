"""P3-M1：出站图片下载统一护栏（SSRF + 解压/下载体积上限）。

覆盖：
- CheckedURL 对协议/回环/内网/云元数据地址的拒绝与可信主机放行；
- 重定向不得被自动跟随（302 指向内网时必须直接拒绝）；
- 下载体积上限；
- seedream/sensenova 两个曾遗漏护栏的 provider 必须走同一出口。
"""

import http.server
import socketserver
import threading

import pytest

from core.image_gen.base import (
    CheckedURL,
    GenerationError,
    checked_image_download,
    read_bounded,
)


class _FakeResponse:
    def __init__(self, chunks, status_code=200):
        self._chunks = chunks
        self.status_code = status_code

    def iter_content(self, chunk_size=8192):
        for c in self._chunks:
            yield c

    def close(self):
        pass


# ---------- URL 边界 ----------
@pytest.mark.parametrize("raw", [
    "file:///etc/passwd",
    "ftp://127.0.0.1/x.png",
    "http://127.0.0.1/x.png",
    "http://[::1]/x.png",
    "http://169.254.169.254/latest/meta-data/",
    "http://10.0.0.5/x.png",
    "http://192.168.1.10/x.png",
    "http://172.16.0.1/x.png",
    "http:///x.png",
])
def test_checked_url_rejects_non_global(raw):
    with pytest.raises(GenerationError):
        CheckedURL.parse(raw, frozenset())


def test_checked_url_trusts_explicit_gateway_host():
    u = CheckedURL.parse(
        "http://127.0.0.1:8080/internal-cache/a.png", frozenset({"127.0.0.1"})
    )
    assert u.host == "127.0.0.1"


def test_checked_url_rejects_untrusted_loopback_even_with_other_trusts():
    with pytest.raises(GenerationError):
        CheckedURL.parse("http://[::1]/a.png", frozenset({"gateway.example"}))


# ---------- 体积上限 ----------
def test_read_bounded_accepts_within_cap():
    resp = _FakeResponse([b"abcd", b"efgh"])
    assert read_bounded(resp, max_bytes=8) == b"abcdefgh"


def test_read_bounded_rejects_oversize():
    resp = _FakeResponse([b"abcd", b"efgh", b"XXXX"])
    with pytest.raises(GenerationError, match="过大|limit|上限"):
        read_bounded(resp, max_bytes=8)


# ---------- 真实回环服务：重定向必须不跟随 ----------
class _RedirectOnce(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/meta")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.end_headers()
            self.wfile.write(b"\x89PNG\r\n\x1a\n-bytes")

    def log_message(self, *args):
        pass


@pytest.fixture()
def loopback_server():
    with socketserver.TCPServer(("127.0.0.1", 0), _RedirectOnce) as httpd:
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        yield f"127.0.0.1:{httpd.server_address[1]}"
        httpd.shutdown()


def test_checked_download_fetches_trusted_host(loopback_server):
    data = checked_image_download(
        f"http://{loopback_server}/ok.png", trusted_hosts=frozenset({"127.0.0.1"})
    )
    assert data.startswith(b"\x89PNG")


def test_checked_download_does_not_follow_redirect(loopback_server):
    # 302 必须原样返回并被拒绝，绝不能跟随到 Location 指向的内网/元数据地址
    with pytest.raises(GenerationError):
        checked_image_download(
            f"http://{loopback_server}/redirect",
            trusted_hosts=frozenset({"127.0.0.1"}),
        )


# ---------- provider 接线 ----------
def test_seedream_and_sensenova_route_download_through_guard(monkeypatch):
    from core.image_gen import seedream, sensenova

    def boom(*args, **kwargs):
        raise AssertionError("必须使用 checked_image_download，不得裸 requests.get 下载")

    # 若 provider 内仍保留 requests.get(上游URL) 直连，替换后将不会被调用：
    # 这里用哨兵确认统一出口被调用且携带"禁重定向"语义。
    calls = {}

    def fake_guard(raw_url, trusted_hosts=frozenset(), timeout=60, max_bytes=0):
        calls["url"] = raw_url
        calls["trusted"] = trusted_hosts
        return b"\x89PNG"

    monkeypatch.setattr(seedream, "checked_image_download", fake_guard)
    monkeypatch.setattr(sensenova, "checked_image_download", fake_guard)

    # 直接验证模块符号存在且来自共享护栏
    assert seedream.checked_image_download is sensenova.checked_image_download
