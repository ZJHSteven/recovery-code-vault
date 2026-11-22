"""用两把DPAPI保护的密钥，分别对比官方age CLI与上游Typage解密结果。

仅给Node子进程stdin传入身份密钥，绝不存明文密钥文件/命令行参数/环境变量。
二进制ZIP只存在父进程内存，验证内部清单而不把它输出到任何日志。
"""
import argparse
import hashlib
import subprocess
from pathlib import Path
from recovery_provision import dpapi_unprotect, validate_plain_zip

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--age",type=Path,required=True)
    p.add_argument("--encrypted",type=Path,required=True)
    p.add_argument("--key-store",type=Path,required=True)
    args=p.parse_args()
    for key_label in ("apple-passwords","cloudflare-access"):
        secret=dpapi_unprotect((args.key_store / (key_label+".agekey.dpapi")).read_bytes())
        age=subprocess.run([str(args.age),"-d","-i","-",str(args.encrypted)],
            input=secret,capture_output=True,check=True,timeout=60).stdout
        js=subprocess.run(["node",str(Path(__file__).resolve().parents[1] / "tests" / "age_js_decrypt.mjs"),
            str(args.encrypted)],input=secret,capture_output=True,check=True,timeout=60).stdout
        if hashlib.sha256(age).digest()!=hashlib.sha256(js).digest():
            raise RuntimeError("官方age CLI与Typage未能还原相同ZIP")
        # 重新核验清单，避免“两个工具都还原同一损坏数据”的假阳性。
        import zipfile, io, json
        with zipfile.ZipFile(io.BytesIO(js)) as z:
            count=len(json.loads(z.read("_vault_manifest.sha256.json"))["files"])
        validate_plain_zip(js,count)
        print("BROWSER_JS_OFFICIAL_AGE_INTEROP_"+key_label.replace("-","_")+"=PASS")
    print("NO_IDENTITY_EXPORTED_TO_LOG=True")

if __name__=="__main__":
    main()

