# RecoveryCode Vault：仅发布密文的恢复入口

本仓库不是任何人的私密恢复码仓库；公开仓只包含静态前端程序、标准 age 密文和安全部署文件，不包含私钥、恢复码明文或明文文件名。

## 为什么单独新建？

旧的 `RecoveryCode` 私有 Git 仓库可能具有历史明文提交，不能直接把它设置为 GitHub Pages 来源；GitHub Pages 站点默认公开可访问，即使仓库本身为私有。迁移全验收前旧仓库保留不变。

## 解密原理

客户端使用 age X25519 加密；网站使用维护者上游 `FiloSottile/typage`（npm `age-encryption`）在浏览器内部解密并提供 ZIP 文件；没有自研加密容器。

私钥保存在使用者**自行选择的独立恢复渠道**，网站从不获得私钥；浏览器不保存其输入。对于没有在新设备预先存储私钥的情况，不能仅凭打开网站恢复数据。

## 本机部署

1. 对照 `scripts/recovery_provision.py`，确认公开目录没有恢复明文。
2. 从原RecoveryCode目录内存打包并加密（不会覆盖或删除原始仓库）。
3. `npm ci && npm run build` 将上游加密库打包进 `docs/decrypt.js`，正式静态站点不依赖Node运行时。
4. `docs/` 同时可以发布到GitHub Pages和Cloudflare Workers Static Assets。
5. 正式撤销旧Git仓库中的明文历史前，必须先在新设备独立解密密文并核验文件SHA256，并完成全部凭据轮换。

不要把 GitHub Pages 当作身份验证系统。后续 Cloudflare Access 可提供独立的身份认证渠道，但它不是 age 解密密钥。
