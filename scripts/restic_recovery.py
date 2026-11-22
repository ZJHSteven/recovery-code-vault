"""为新restic v2仓库生成六个彼此独立的密码槽，全部先保存在Windows DPAPI中。

通过 `--emit-for-engine <slot>` 输出到受信任的备份引擎管道，
不在CLI argv、公开仓库、Windows命令行历史或日志中放密码本身。
密码槽不是Shamir分片：任意一个槽的密码均可解封同一个Master Key。

新repo云端验收还没有通过，所以这个本地仓库仍只是“预发行候选”；
绝不能因此注销旧自研v1六份密钥，也不能据此删除旧备份。
"""

from __future__ import annotations
import argparse
import os
from pathlib import Path
import secrets
import subprocess
import sys
from recovery_provision import dpapi_protect, dpapi_unprotect

SLOTS=(
    "local",
    "apple-passwords",
    "cloudflare-access",
    "github-vault",
    "offline-usb",
    "emergency-print",
)

def password_file(store:Path,name:str)->Path:
    if name not in SLOTS:raise ValueError("未知的恢复密钥槽名称")
    return store / (name+".password.dpapi")

def obtain_password(store:Path,name:str)->str:
    path=password_file(store,name)
    raw=dpapi_unprotect(path.read_bytes()).decode("ascii").strip()
    if not raw.startswith("rv26-") or len(raw)<40:
        raise RuntimeError("本地密钥槽格式不正确")
    return raw

def provision_passwords(store:Path)->None:
    store.mkdir(parents=True,exist_ok=True)
    for name in SLOTS:
        dest=password_file(store,name)
        if not dest.exists():
            secret="rv26-"+secrets.token_urlsafe(32)
            protected=dpapi_protect((secret+"\n").encode("ascii"))
            fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_BINARY,0o600)
            try:
                os.write(fd,protected)
                os.fsync(fd)
            finally:
                os.close(fd)
    unique={obtain_password(store,n) for n in SLOTS}
    if len(unique)!=len(SLOTS):raise RuntimeError("恢复密码出现碰撞，禁止初始化仓库")

def engine_command(script:Path,store:Path,name:str)->str:
    # 不将明文嵌入shell/argv；只有脚本路径和非秘密槽名出现在进程参数。
    # restic/rustic会执行并抓取stdout密码，因此这个函数只能作为本机信任边界。
    return f'python "{script}" --emit-for-engine {name} --key-store "{store}"'

def checked(args:list[str],env:dict[str,str]|None=None)->None:
    r=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180)
    if r.returncode!=0:
        # stdout/stderr可能包含错误上下文，不回显以防工具意外将秘密输出。
        raise RuntimeError("备份引擎调用失败；详细内容已隐藏防止密钥泄露")

def new_repo(repo:Path,store:Path,rustic:Path,restic:Path)->None:
    if repo.exists():
        raise RuntimeError("目标仓库路径已存在，拒绝生成第二个Master Key或覆盖旧仓")
    provision_passwords(store)
    self_script=Path(__file__).resolve()
    root_cmd=engine_command(self_script,store,SLOTS[0])
    repo.parent.mkdir(parents=True,exist_ok=True)
    # Rust原生Rustic初始化正式restic-v2格式；Go原版Restic独立验证每个槽。
    checked([str(rustic),"init","--set-version","2","--repository",str(repo),
        "--password-command",root_cmd])
    for name in SLOTS[1:]:
        new_cmd=engine_command(self_script,store,name)
        checked([str(rustic),"key","add","--repository",str(repo),
            "--password-command",root_cmd,
            "--new-password-command",new_cmd])
    for name in SLOTS:
        cmd=engine_command(self_script,store,name)
        checked([str(restic),"--repo",str(repo),"--password-command",cmd,"check"])
    print("NEW_RESTIC_V2_REPOSITORY_INITIALIZED=True")
    print("INDEPENDENT_PASSWORD_SLOTS_VERIFIED="+str(len(SLOTS)))
    print("GO_RESTIC_ORIGINAL_BINARY_CHECK_ALL_SLOTS=PASS")
    print("NEW_MASTER_KEY_SHARED_BY_ALL_SLOTS=True")
    print("IMPORTANT=新仓库尚未真实上传到PikPak，旧仓恢复码不能停用")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--emit-for-engine",choices=SLOTS)
    parser.add_argument("--provision",action="store_true")
    parser.add_argument("--repo",type=Path)
    parser.add_argument("--key-store",type=Path,required=True)
    parser.add_argument("--rustic",type=Path)
    parser.add_argument("--restic",type=Path)
    args=parser.parse_args()
    if args.emit_for_engine:
        # 交互式终端不允许误输入私钥；只有被Restic/Rustic捕获的stdout管道。
        if sys.stdout.isatty():
            raise SystemExit("禁止在终端屏幕直接显示恢复密钥，请走加密恢复金库")
        sys.stdout.write(obtain_password(args.key_store,args.emit_for_engine)+"\n")
        return
    if not (args.provision and args.repo and args.rustic and args.restic):
        raise SystemExit("签发六槽必须指定 --provision、--repo、--rustic、--restic")
    new_repo(args.repo,args.key_store,args.rustic,args.restic)

if __name__=="__main__":
    main()
