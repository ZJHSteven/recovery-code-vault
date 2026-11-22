"""将第二把age身份密钥通过stdin直接注册到Cloudflare Secrets Store。

与服务器端公开静态Worker完全不同：这个脚本将密钥保存在Cloudflare
**受限Secrets Store** 中，公开加密网站不持有读取它的binding。

绝不把私钥写入命令行 argv、PowerShell history、临时文件、日志或Git。
没有--value参数（Cloudflare官方明确警告它会泄露到shell history）。
此阶段只创建安全存储，不等于已经创建了受Access保护的领取接口；
那需要另行将binding加到专用的认证Worker，并实机验签。
"""
from __future__ import annotations
import argparse
from pathlib import Path
import shutil
import subprocess
from recovery_provision import dpapi_unprotect

STORE_ID="b467c96447d446f393f9f4dfe5527d3f"
SECRET_NAME="RECOVERY_VAULT_AGE_IDENTITY_CF_2026"

def run(args:list[str], input_bytes:bytes|None=None)->subprocess.CompletedProcess:
    return subprocess.run(args,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        timeout=180,check=False)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--key-store",type=Path,required=True)
    args=parser.parse_args()
    wrangler=shutil.which("wrangler")
    if not wrangler:
        raise RuntimeError("未安装Wrangler，拒绝从其他途径暴露私钥")
    list_args=[wrangler,"secrets-store","secret","list",STORE_ID,
        "--remote","--per-page","100"]
    existing=run(list_args)
    if existing.returncode!=0:
        raise RuntimeError("不能确认Cloudflare旧Secret列表，拒绝覆盖")
    if SECRET_NAME.encode() in existing.stdout:
        print("CFSS_SECRET_ALREADY_EXISTS_NO_OVERWRITE=True")
        return
    private=dpapi_unprotect(
        (args.key_store/"cloudflare-access.agekey.dpapi").read_bytes()
    ).strip()
    if not private.startswith(b"AGE-SECRET-KEY-"):
        raise RuntimeError("DPAPI保管的身份格式不正确")
    result=run([
        wrangler,"secrets-store","secret","create",STORE_ID,
        "--name",SECRET_NAME,
        "--scopes","workers","--remote",
        "--comment","RecoveryCode age X25519 identity; must be released only behind verified CF Access"
    ],private+b"\n")
    # stdout/stderr都可能包含Wrangler交互UI，绝不透传。
    if result.returncode!=0:
        raise RuntimeError("CFSS注册失败；详细工具输出已隐藏以防止私钥泄露")
    # 写入完成后立刻再用仅元数据列表核验目标Secret确实存在。
    check=run(list_args)
    if check.returncode!=0 or SECRET_NAME.encode() not in check.stdout:
        raise RuntimeError("CFSS返回后无法确认远端Secret存在")
    print("CFSS_AGE_IDENTITY_REGISTERED=True")
    print("PRIVATE_KEY_IN_COMMAND_LINE=False")
    print("PRIVATE_KEY_IN_PUBLIC_STATIC_WORKER=False")
    print("NOTE=Access领取接口仍须单独绑定并进行本人身份验证")

if __name__=="__main__":
    main()
