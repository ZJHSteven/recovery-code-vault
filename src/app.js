// 浏览器端独立恢复：只使用上游Typage的age标准实现（不是自创加密）。
// 这份源码经esbuild打包成docs/decrypt.js，部署后无需Node.js运行时或外部CDN。
// 恢复密钥仅存在当前浏览器内存中，绝不保存localStorage/cookie、POST或打日志。
// GitHub Pages/Cloudflare都只保存公开可下载的age密文和本工具静态资源。
import { Decrypter } from "age-encryption";

const keyInput = document.querySelector("#identity");
const recoverButton = document.querySelector("#recover");
const status = document.querySelector("#status");
const filePicker = document.querySelector("#encryptedFile");
const sourceLabel = document.querySelector("#sourceLabel");

function setStatus(message, error = false) {
  status.textContent = message;
  status.dataset.level = error ? "error" : "info";
}

// 若用户选择了本地密文，就根本不访问云端；
// 否则只从当前站点同源读取vault.age，不使用跨域CDN。
async function readEncryptedFile() {
  if (filePicker.files?.length) {
    sourceLabel.textContent = "选择的本地加密文件";
    return new Uint8Array(await filePicker.files[0].arrayBuffer());
  }
  sourceLabel.textContent = "当前站点提供的加密文件";
  const response = await fetch(new URL("./vault.age", location.href), {
    cache: "no-store",
    credentials: "omit",
    redirect: "error",
  });
  if (!response.ok) {
    throw new Error("无法读取密文文件，请选择已另行保存的 .age 文件");
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function recover() {
  if (recoverButton.disabled) return;
  const identity = keyInput.value.trim();
  if (!identity) {
    setStatus("请输入从独立安全渠道取回的 age 身份密钥", true);
    return;
  }
  recoverButton.disabled = true;
  setStatus("正在本机浏览器内存中验证和解密……");
  try {
    const encrypted = await readEncryptedFile();
    if (!encrypted.length || encrypted.length > 150 * 1024 * 1024) {
      throw new Error("密文为空或超出浏览器安全大小限制（150 MiB）");
    }
    const decoder = new Decrypter();
    decoder.addIdentity(identity);
    const output = await decoder.decrypt(encrypted);
    const zip = typeof output === "string"
      ? new TextEncoder().encode(output)
      : output;
    if (!(zip instanceof Uint8Array) || zip.length < 4 ||
        zip[0] !== 0x50 || zip[1] !== 0x4b) {
      throw new Error("已解密数据不是预期的 ZIP 恢复归档");
    }
    const objectUrl = URL.createObjectURL(
      new Blob([zip], { type: "application/zip" })
    );
    const link = document.createElement("a");
    link.href = objectUrl;
    link.download = "recovery-vault.zip";
    document.body.append(link);
    link.click();
    link.remove();
    // 浏览器下载已触发后立即撤销临时对象链接。
    setTimeout(() => URL.revokeObjectURL(objectUrl), 3000);
    keyInput.value = "";
    setStatus("解密成功。已在本机生成 ZIP 文件，请在可信设备查看内容。");
  } catch {
    // 不回显age库原始异常对象，防止浏览器控制台和界面泄露意外密钥内容。
    setStatus("解密失败：请核对身份密钥是否属于此金库，或密文是否完整。", true);
  } finally {
    recoverButton.disabled = false;
  }
}

recoverButton.addEventListener("click", recover);
keyInput.addEventListener("keydown", (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key === "Enter") recover();
});
setStatus("等待恢复密钥；无需登录当前云端站点");

