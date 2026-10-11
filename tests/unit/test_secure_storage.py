"""P3-H3：保险库主密钥不再由 HOSTNAME/USER 等非秘密信息确定性推导。

- 主密钥为首次启动生成的随机 Fernet key，独立存放于 0600 权限文件，
  路径可用 LIVE2D_VAULT_KEY_FILE 覆盖；
- 两个安装实例的密钥不同，密文不可交叉解密；
- 旧版（确定性推导）保险库仍可读，并在首次启动时原地升级为新密钥加密。
"""

import base64
import json
import os
import stat
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")
from cryptography.fernet import Fernet  # noqa: E402

from core import secure_storage  # noqa: E402
from core.secure_storage import EncryptedConfig, SecureStorage  # noqa: E402


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    key_file = tmp_path / "keys" / "vault.key"
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.setenv("LIVE2D_VAULT_KEY_FILE", str(key_file))
    monkeypatch.setenv("LIVE2D_PROJECT_ROOT", str(project))
    return {"key_file": key_file, "project": project, "root": tmp_path}


def test_master_key_is_random_file_with_owner_only_perms(isolated_home):
    s = SecureStorage()
    assert s.encrypt("hello") != s.encrypt("hello")  # Fernet 随机 IV
    assert s.decrypt(s.encrypt("hello")) == "hello"

    kf = isolated_home["key_file"]
    assert kf.exists(), "主密钥必须落盘到独立文件"
    raw = kf.read_bytes().strip()
    # 必须是合法 Fernet key（32 字节的 urlsafe base64）
    assert len(base64.urlsafe_b64decode(raw)) == 32

    if os.name != "nt":
        mode = stat.S_IMODE(kf.stat().st_mode)
        assert mode == 0o600, f"密钥文件权限必须 0600，实得 {oct(mode)}"
        parent_mode = stat.S_IMODE(kf.parent.stat().st_mode)
        assert parent_mode == 0o700, f"密钥目录权限必须 0700，实得 {oct(parent_mode)}"


def test_key_persists_between_instances(isolated_home):
    token = SecureStorage().encrypt("roundtrip-secret")
    # 新实例从同一密钥文件加载，应能解开旧密文
    assert SecureStorage().decrypt(token) == "roundtrip-secret"


def test_different_installations_cannot_cross_decrypt(tmp_path, monkeypatch):
    kf_a = tmp_path / "a" / "vault.key"
    kf_b = tmp_path / "b" / "vault.key"
    monkeypatch.setenv("LIVE2D_VAULT_KEY_FILE", str(kf_a))
    token_a = SecureStorage().encrypt("machine-a-secret")

    monkeypatch.setenv("LIVE2D_VAULT_KEY_FILE", str(kf_b))
    assert SecureStorage().decrypt(token_a) is None, "不同机器/安装的密钥必须不可交叉解密"


def _write_legacy_vault(vault_path: Path, data: dict) -> None:
    """用旧版确定性算法（系统信息盐 + 硬编码口令）加密写一个历史保险库。"""
    s = SecureStorage()
    legacy_key = s._derive_legacy_key()
    token = Fernet(legacy_key).encrypt(
        json.dumps(data, ensure_ascii=False).encode("utf-8")
    )
    vault_path.write_bytes(base64.urlsafe_b64encode(token))


def test_legacy_vault_reads_via_fallback(isolated_home):
    vault = isolated_home["project"] / ".env.encrypted"
    _write_legacy_vault(vault, {"openai": "sk-legacy-readable"})

    s = SecureStorage()
    # 新密钥解不开，但必须回退到旧算法读出（升级期间不丢密钥）
    assert s.get_api_key("openai", str(vault)) == "sk-legacy-readable"


def test_upgrade_file_reencrypts_with_random_key(isolated_home):
    vault = isolated_home["project"] / ".env.encrypted"
    _write_legacy_vault(vault, {"openai": "sk-upgrade-me", "ark": "ark-xyz"})

    s = SecureStorage()
    assert s.upgrade_file(str(vault)) is True

    new_key = isolated_home["key_file"].read_bytes().strip()
    token = vault.read_text(encoding="utf-8")
    # 升级后必须能被新随机密钥直接解开
    assert json.loads(Fernet(new_key).decrypt(base64.urlsafe_b64decode(token))) == {
        "openai": "sk-upgrade-me", "ark": "ark-xyz",
    }
    # 且旧确定性密钥再也解不开（证明确实换了密钥）
    legacy = Fernet(s._derive_legacy_key())
    with pytest.raises(cryptography.fernet.InvalidToken):
        legacy.decrypt(base64.urlsafe_b64decode(token))

    # 幂等：再升一次不改内容、不报错
    assert s.upgrade_file(str(vault)) is False


def test_encrypted_config_auto_upgrades_on_startup(isolated_home):
    vault = isolated_home["project"] / ".env.encrypted"
    _write_legacy_vault(vault, {"openai": "sk-auto-upgrade"})

    cfg = EncryptedConfig()
    assert cfg.get_api_key("openai") == "sk-auto-upgrade"

    # 启动后保险库应已是新密钥方案（用独立实例验证，不依赖读时回退）
    fresh = SecureStorage()
    assert fresh._decrypt_with_current_key(vault.read_text(encoding="utf-8")) == (
        json.dumps({"openai": "sk-auto-upgrade"}, ensure_ascii=False)
    )


def test_missing_vault_upgrade_is_noop(isolated_home):
    s = SecureStorage()
    assert s.upgrade_file(str(isolated_home["project"] / "nope.enc")) is False
