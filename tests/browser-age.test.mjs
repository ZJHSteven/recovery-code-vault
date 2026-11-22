import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { Encrypter, Decrypter, generateIdentity, identityToRecipient } from "age-encryption";

test("上游Typage年龄文件X25519客户端加密与恢复完整性", async () => {
  const identity = await generateIdentity();
  const recipient = await identityToRecipient(identity);
  const input = new TextEncoder().encode("仅用于合成测试，不包含任何用户恢复码");
  const e = new Encrypter();
  e.addRecipient(recipient);
  const ciphertext = await e.encrypt(input);
  assert.ok(ciphertext instanceof Uint8Array);
  const d = new Decrypter();
  d.addIdentity(identity);
  const recovered = await d.decrypt(ciphertext);
  assert.deepEqual(Buffer.from(recovered), Buffer.from(input));
  assert.ok(!Buffer.from(ciphertext).includes(Buffer.from(input)));
});

test("公开静态HTML严格限制第三方请求且不嵌入密钥", () => {
  const html = readFileSync(new URL("../docs/index.html", import.meta.url), "utf8");
  assert.match(html, /connect-src 'self'/);
  assert.match(html, /default-src 'none'/);
  assert.match(html, /script-src 'self'/);
  assert.doesNotMatch(html, /http-equiv=["']refresh/);
  assert.doesNotMatch(html, /<script[^>]*https?:\/\//);
  assert.doesNotMatch(html, /<form[^>]+action/);
  const app = readFileSync(new URL("../src/app.js", import.meta.url), "utf8");
  assert.doesNotMatch(app, /\blocalStorage\b\s*\./);
  assert.doesNotMatch(app, /\bconsole\.log\s*\(/);
  assert.doesNotMatch(app, /\bmethod:\s*["']POST/);
});

