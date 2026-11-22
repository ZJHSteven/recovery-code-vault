// 验证真实磁盘密文与TyPage浏览器JavaScript库互操作。
// **严格禁止打印密钥或ZIP内容到stderr**。
// 密钥只能通过stdin传入，密文文件通过argv中的路径读取，ZIP二进制仅送stdout
// 给本机验证程序检查内容哈希。此文件不能在普通终端直接手动运行。
import { Decrypter } from "age-encryption";
import { readFileSync } from "node:fs";

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const identity = Buffer.concat(chunks).toString("utf8").trim();
const encrypted = readFileSync(process.argv[2]);
try {
  const decryptor = new Decrypter();
  decryptor.addIdentity(identity);
  const result = await decryptor.decrypt(new Uint8Array(encrypted));
  process.stdout.write(Buffer.from(result));
} catch {
  process.stderr.write("标准age浏览器JS互操作失败（已隐藏敏感信息）\n");
  process.exitCode = 1;
}

