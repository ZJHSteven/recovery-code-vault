#!/usr/bin/env python3
"""RecoveryCode -> age 标准密文归档，一次性离线迁移工具。

安全边界：
1. 只读取原始 RecoveryCode 工作树，从不改动它的文件或Git历史；
2. 将所有路径、内容、SHA-256核对清单装入内存ZIP；不会产生磁盘明文ZIP；
3. 使用官方下载的 age.exe X25519 多recipient格式加密；
4. 两把独立私钥只保存为当前 Windows 用户 DPAPI 加密的文件，不写入公开仓库；
5. 分别使用两把私钥实际解密同一份密文，且每个文件的SHA256都需要匹配；
6. 显示的日志只有文件数量、总大小和密文摘要，不能泄露文件名/私钥。

重要局限：DPAPI只绑定当前Windows用户，**不是离机备份**。
私钥仍须另外保存到Apple密码、CFSS或物理离线介质且独立验证之后，
才有资格把这份云端密文称为可容灾恢复。
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path


if sys.platform != "win32":
    raise SystemExit("此部署工具仅支持Windows DPAPI；最终解密格式age可跨平台使用")


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


CRYPT32 = ctypes.WinDLL("crypt32", use_last_error=True)
KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
CRYPT32.CryptProtectData.argtypes = [
    ctypes.POINTER(DataBlob), ctypes.c_wchar_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob),
]
CRYPT32.CryptProtectData.restype = wintypes.BOOL
CRYPT32.CryptUnprotectData.argtypes = [
    ctypes.POINTER(DataBlob), ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(DataBlob),
]
CRYPT32.CryptUnprotectData.restype = wintypes.BOOL
KERNEL32.LocalFree.argtypes = [ctypes.c_void_p]
KERNEL32.LocalFree.restype = ctypes.c_void_p


def _blob(data: bytes) -> tuple[DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    return DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def dpapi_protect(plaintext: bytes) -> bytes:
    source, keep_alive = _blob(plaintext)
    destination = DataBlob()
    if not CRYPT32.CryptProtectData(
        ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)
    ):
        raise OSError("Windows DPAPI Protect失败")
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        KERNEL32.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))


def dpapi_unprotect(ciphertext: bytes) -> bytes:
    source, keep_alive = _blob(ciphertext)
    destination = DataBlob()
    if not CRYPT32.CryptUnprotectData(
        ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)
    ):
        raise OSError("Windows DPAPI Unprotect失败，可能使用了其他Windows身份")
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        KERNEL32.LocalFree(ctypes.cast(destination.pbData, ctypes.c_void_p))


def obtain_identity(keygen: Path, store: Path, label: str) -> tuple[str, str]:
    """新建密钥前检查是否已存在；重复运行不轮换或覆盖任何密钥。

    私钥绝不会出现在工具stdout、repo目录、Git或命令行argv里。
    """
    key_file = store / (label + ".agekey.dpapi")
    recipient_file = store / (label + ".recipient")
    if key_file.exists() != recipient_file.exists():
        raise ValueError("已有密钥与公钥不成对，拒绝自动重置，以免造成无法恢复")
    if not key_file.exists():
        p = subprocess.run([str(keygen)], capture_output=True, check=True, timeout=20)
        raw = (p.stdout + b"\n" + p.stderr).decode("utf-8", errors="replace")
        private = re.search(r"AGE-SECRET-KEY-1[A-Z0-9]+", raw)
        public = re.search(r"age1[023456789acdefghjklmnpqrstuvwxyz]{40,}", raw)
        if not private or not public:
            raise ValueError("官方age-keygen输出格式无法识别，未持久化密钥")
        protected = dpapi_protect((private.group(0) + "\n").encode())
        store.mkdir(parents=True, exist_ok=True)
        # O_EXCL防止并发部署意外覆盖之前有效的恢复密钥。
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_BINARY, 0o600)
        try:
            os.write(fd, protected)
            os.fsync(fd)
        finally:
            os.close(fd)
        recipient_file.write_text(public.group(0) + "\n", encoding="ascii")
    private_key = dpapi_unprotect(key_file.read_bytes()).decode("ascii").strip()
    recipient = recipient_file.read_text(encoding="ascii").strip()
    if not private_key.startswith("AGE-SECRET-KEY-") or not recipient.startswith("age1"):
        raise ValueError("密钥文件格式不正确")
    return private_key, recipient


def build_zip_in_memory(
    source: Path, restic_store: Path | None = None,
    legacy_recovery_dir: Path | None = None,
) -> tuple[bytes, int, int]:
    """加密前的ZIP只存在内存中，不写入硬盘以免残留恢复码明文。"""
    if not source.is_dir() or not (source / ".git").exists():
        raise ValueError("必须明确指向原版RecoveryCode的Git工作树")
    paths = sorted(
        p for p in source.rglob("*")
        if p.is_file() and ".git" not in p.relative_to(source).parts
    )
    for p in paths:
        if p.is_symlink():
            raise ValueError("安全限制：源目录不能包含指向外部的符号链接")
    total = sum(p.stat().st_size for p in paths)
    if total > 256 * 1024 * 1024:
        raise ValueError("恢复码原始目录超出256MiB，避免内存归档意外耗尽内存")
    archive = io.BytesIO()
    manifest: dict[str, object] = {"format": "recovery-vault-zip-v1", "files": {}}
    legacy_files = (
        sorted(legacy_recovery_dir.glob("*.recovery-key.txt"))
        if legacy_recovery_dir is not None else []
    )
    if legacy_recovery_dir is not None and not legacy_files:
        raise ValueError("没有找到旧格式恢复码，拒绝声称旧仓已经得到异地备份")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for path in paths:
            relative = path.relative_to(source).as_posix()
            content = path.read_bytes()
            z.writestr(relative, content)
            manifest["files"][relative] = hashlib.sha256(content).hexdigest()
        for path in legacy_files:
            if not path.is_file() or path.is_symlink():
                raise ValueError("旧恢复码必须是本机普通文件")
            content=path.read_bytes()
            relative="legacy-pikpak-v1-keys/"+path.name
            z.writestr(relative,content)
            manifest["files"][relative]=hashlib.sha256(content).hexdigest()
        if restic_store is not None:
            # 新Restic六份密码只存在DPAPI或本内存归档，绝不生成明文 .txt。
            # 目录名仅在整个age文件解密后的ZIP内部可见。
            from restic_recovery import SLOTS, obtain_password
            for name in SLOTS:
                text=obtain_password(restic_store,name).encode("ascii")+b"\n"
                relative="new-restic-v2-recovery/"+name+".password.txt"
                z.writestr(relative,text)
                manifest["files"][relative]=hashlib.sha256(text).hexdigest()
        z.writestr(
            "_vault_manifest.sha256.json",
            json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2),
        )
    return (
        archive.getvalue(),
        len(paths)+len(legacy_files)+(len(SLOTS) if restic_store is not None else 0),
        total+sum(p.stat().st_size for p in legacy_files),
    )


def validate_plain_zip(plaintext: bytes, count: int) -> None:
    """验证每个文件和归档内加密清单，不能仅以ZIP格式可打开作为成功。"""
    with zipfile.ZipFile(io.BytesIO(plaintext)) as z:
        manifest = json.loads(z.read("_vault_manifest.sha256.json"))
        expected = manifest["files"]
        if len(expected) != count:
            raise ValueError("ZIP中恢复文件数量与原始源不一致")
        if set(z.namelist()) != set(expected) | {"_vault_manifest.sha256.json"}:
            raise ValueError("ZIP文件集合与清单不一致，可能缺失或混入额外文件")
        for name, digest in expected.items():
            if hashlib.sha256(z.read(name)).hexdigest() != digest:
                raise ValueError("归档内SHA256校验未通过")


def main() -> None:
    parser = argparse.ArgumentParser(description="内存归档→age加密→两把独立私钥完整解密验证")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--publish", type=Path, required=True)
    parser.add_argument("--age", type=Path, required=True)
    parser.add_argument("--age-keygen", type=Path, required=True)
    parser.add_argument("--key-store", type=Path, required=True)
    parser.add_argument("--restic-key-store", type=Path,
        help="可选：把新restic仓六份DPAPI密码直接写进age加密前的内存ZIP")
    parser.add_argument("--legacy-recovery-dir", type=Path,
        help="可选：把旧PikPak v1恢复码也装进同一份age密文，直到旧仓恢复验收完成")
    args = parser.parse_args()

    args.publish.parent.mkdir(parents=True, exist_ok=True)
    source = args.source.resolve(strict=True)
    if args.publish.is_relative_to(source):
        raise ValueError("不能把归档输出写回包含明文的旧RecoveryCode源目录")
    identities = [
        obtain_identity(args.age_keygen, args.key_store, "apple-passwords"),
        obtain_identity(args.age_keygen, args.key_store, "cloudflare-access"),
    ]
    bundle, count, size = build_zip_in_memory(
        source,args.restic_key_store,args.legacy_recovery_dir)
    encrypted = subprocess.run(
        [str(args.age), "-r", identities[0][1], "-r", identities[1][1]],
        input=bundle, capture_output=True, check=True, timeout=40,
    ).stdout
    if not encrypted.startswith(b"age-encryption.org/v1\n"):
        raise ValueError("age命令生成的不是标准age-v1密文")
    # 不允许持久化ZIP明文；先持久化只有密文的临时文件，
    # 以便age能够用 -i - 从stdin接收私钥、从磁盘文件读取密文。
    fd, tmp_name = tempfile.mkstemp(prefix=".vault-age-", suffix=".tmp", dir=args.publish.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(encrypted)
            output.flush()
            os.fsync(output.fileno())
        # 先在临时密文上验证两把独立密钥均可成功解密。
        for private, _ in identities:
            p = subprocess.run(
                [str(args.age), "-d", "-i", "-", tmp_name],
                input=(private + "\n").encode("ascii"),
                capture_output=True, timeout=60,
            )
            if p.returncode != 0:
                raise ValueError("至少一把age独立身份无法解密同一密文归档")
            validate_plain_zip(p.stdout, count)
            if hashlib.sha256(p.stdout).digest() != hashlib.sha256(bundle).digest():
                raise ValueError("age解密结果与内存原始ZIP字节不一致")
        os.replace(tmp_name, args.publish)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

    print("AGE_MULTI_RECIPIENT_VAULT_VERIFIED=True")
    print("INDEPENDENT_IDENTITIES_TESTED=2")
    print("SOURCE_FILES_ENCRYPTED=" + str(count))
    print("SOURCE_TOTAL_BYTES=" + str(size))
    print("ENCRYPTED_BYTES=" + str(len(encrypted)))
    print("CIPHERTEXT_SHA256=" + hashlib.sha256(encrypted).hexdigest())
    print("UNENCRYPTED_ARCHIVE_WRITTEN_TO_DISK=False")
    print("WARNING=DPAPI只支持本机Windows账户；Apple与CFSS离机身份登记仍须完成")


if __name__ == "__main__":
    main()
