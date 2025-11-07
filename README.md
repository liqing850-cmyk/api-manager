# API Manager Worker

完整 Cloudflare Worker 重写自 PHP 接口管理应用。使用 KV 存储用户、API、影视源、代理。支持认证、CRUD 操作、状态检查、JSON 导出、采集功能。

## 特性

- 用户注册/登录/修改密码 (PBKDF2 哈希)
- 接口聚合管理 (添加/编辑/删除/检查/排序/去重)
- 影视源配置 (类似，支持导入 JSON)
- 代理管理 (自建/AllOrigins，支持检查)
- 影视采集 (代理支持，分类解析)
- JSON 导出 (TVBox 兼容)

## 部署

1. 安装 Wrangler: `npm i -g wrangler`
2. 在 Cloudflare Dashboard 创建 5 个 KV 命名空间 (USERS_KV, APIS_KV, VIDEO_SOURCES_KV, PROXIES_KV, JSON_EXPORT_KV)，更新 `wrangler.toml`
3. `wrangler deploy`

## 注意

- 会话使用 Bearer Token (24h 过期)
- 状态检查使用 HEAD 请求
- 前端单页应用，动态加载部分
- 测试增量部署；扩展 IDN 支持 (punycode)
- 无外部依赖；所有 CSS/JS/HTML 嵌入

## 文件结构

- `src/worker.js`: 主 Worker 逻辑
- `wrangler.toml`: 配置
- `package.json`: 依赖 (wrangler)

## 贡献

Fork & PR 完整功能。
