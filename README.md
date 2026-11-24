# teleagent2api

把本机已经登录的 TeleAgent 3.0.0-rc.1 转成只监听本机的 OpenAI 和 Anthropic 兼容网关。

它不实现天翼账号登录，也不接收手机号或验证码。程序只读取当前平台上 TeleAgent 已保存的登录状态，并代发官方模型请求。

## 当前状态

| 平台 | 零配置 | 实测 |
|---|---|---|
| Linux / WSL | 可以。读取 `local-key` 与 `token.json` | `/health`、模型列表、流式对话、三个模型、工具调用及工具结果回传通过 |
| Windows | 可以。`scheme=safe_storage` 用当前用户的 DPAPI 解开 `Local State` 里的 `os_crypt` 密钥，再解 `v10` 密文 | 用本机 Windows 登录态签名后，`user_info`、模型目录和 `chat-flash` 流式对话返回 HTTP 200 |
| 网页 | 桌面 `token.json` 不存在或已过期时，读取 TeleAgent 与 Chrome / Edge 里的 `operationToken` 或 `x-token` | 桌面程序里的这枚 Cookie 与桌面 JWT 是同一枚。浏览器里过期的 Cookie 不会拿来签名 |

## 运行

要求本机 TeleAgent 已登录。只允许监听回环地址。

```bash
go build -o teleagent2api .
./teleagent2api -addr 127.0.0.1:8787
```

Linux 自动搜索：

```text
~/.local/share/TeleAgent/app-auth/device-meta.json
~/.local/share/TeleAgent/users/*/app-auth/token.json
~/.local/share/TeleAgent/users/*/app-auth/local-key
```

Windows 自动搜索：

```text
%USERPROFILE%\.local\share\TeleAgent\app-auth\device-meta.json
%USERPROFILE%\.local\share\TeleAgent\users\*\app-auth\token.json
%USERPROFILE%\.local\share\TeleAgent\Local State
%APPDATA%\TeleAgent\app-auth\device-meta.json
```

Windows 的 `scheme=safe_storage` 不使用 Linux 的 `local-key`。密文以 `v10` 开头，密钥放在同一用户目录的 `Local State`，并且只由这个 Windows 用户的 DPAPI 保护。在 Windows 上直接调用 `CryptUnprotectData`。从 WSL 启动时，如果当前系统没有可用的桌面登录态，会通过 `powershell.exe` 解开同一位 Windows 用户的登录态。

网页端不另做登录。网关读取已经写在本机的 Cookie：

```text
TeleAgent/Partitions/*/Cookies
TeleAgent/Network/Cookies
Chrome、Edge 的 Network/Cookies
```

只用主机 `agent.teleai.com.cn` 上的 `operationToken` 或 `x-token`。桌面登录文件可用时优先用桌面 JWT。Cookie 过期时会跳过。

## 令牌续期

桌面 JWT 会过期。官方客户端在进程运行期间，每个本地日最多请求一次 `POST /cowork/auth/token-refresh`，成功后把新的 accessToken 写回 `token.json` 和同文件里的 `encryptedMeta`。会话还有一个大约 90 天的绝对期限，过了这个期限必须重新登录。

网关使用同一条规则。启动时以及之后每 6 小时检查 `users/*/app-auth/renewal-schedule.json`。如果今天还没有尝试过，就续期并写回原来的 `token.json`。桌面客户端当天已经写过这个日期时，网关不再请求，避免把正在使用的令牌轮换掉。网页 Cookie 不会被续期，也不会被改写。显式传入 `-auth-state` 或 `TELEAGENT_SESSION_KEY` 时不碰桌面登录文件。

```bash
TELEAGENT_REFRESH=0 ./teleagent2api -addr 127.0.0.1:8787
```

可选的显式输入只用于调试：

```bash
TELEAGENT_SESSION_KEY='本机会话密钥' \
  ./teleagent2api -auth-state /path/to/encrypted-auth-state.json
```

不要把 token、会话密钥、installId 或 deviceId 发到日志、对话或远程服务。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/health` | 网关存活 |
| GET | `/v1/models` | OpenAI 模型目录。带 `anthropic-version` 请求头时返回 Anthropic 模型目录 |
| GET | `/v1/models?format=codex` | Codex 可加载的模型目录 |
| POST | `/v1/chat/completions` | OpenAI Chat Completions |
| POST | `/v1/responses` | OpenAI Responses |
| POST | `/v1/messages` | Anthropic Messages |
| POST | `/v1/messages/count_tokens` | 估算 Anthropic 请求的输入 token 数 |

对话示例：

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"chat-pro","stream":true,"messages":[{"role":"user","content":"Reply with pong only."}]}'
```

支持 `messages`、文本数组、`tools`、`tool_choice`、`tool_calls` 和工具结果回传。`chat-pro` 实测不支持温度、推理和附件，但支持工具调用。可用模型为 `chat-pro`、`chat-flagship`、`chat-flash`。

三种对话入口均支持 JSON 和 SSE 响应，以及客户端工具定义、调用参数和结果回传。Responses 请求需在 `input` 中带上本轮所需的完整历史。令牌估算用于 Claude Code 的上下文管理，实际用量来自上游。

## Claude Code

网关启动后，在希望使用 Claude Code 的目录运行：

```bash
claude --settings '{"env":{"ANTHROPIC_BASE_URL":"http://127.0.0.1:8787","ANTHROPIC_AUTH_TOKEN":"local","CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY":"1"}}' \
  --model teleagent-anthropic/chat-pro
```

`/model` 会从网关发现模型。Anthropic 目录为模型加上 `teleagent-anthropic/` 前缀，以匹配 Claude Code 的发现规则。网关把这些 ID 映射到原始 TeleAgent 模型。也可以直接用 `--model chat-pro`。[`/model` 发现规则](https://code.claude.com/docs/en/llm-gateway-protocol#model-discovery)

## Codex

获取模型目录，并在启动时将它交给 Codex 的 `model_catalog_json`。[Codex 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)

```bash
catalog="$HOME/.codex/teleagent-models.json"
mkdir -p "$(dirname "$catalog")"
curl -fsS 'http://127.0.0.1:8787/v1/models?format=codex' -o "$catalog" &&
  TELEAGENT_API_KEY=local codex -m chat-pro \
    -c "model_catalog_json=\"$catalog\"" \
    -c 'model_provider="teleagent"' \
    -c 'model_providers.teleagent.name="TeleAgent"' \
    -c 'model_providers.teleagent.base_url="http://127.0.0.1:8787/v1"' \
    -c 'model_providers.teleagent.wire_api="responses"' \
    -c 'model_providers.teleagent.env_key="TELEAGENT_API_KEY"'
```

Claude Code 和 Codex 示例中的 `local` 是客户端占位值。上游认证由网关读取本机 TeleAgent 登录态完成。

## 上游

```text
POST https://agent.teleai.com.cn/superCowork/sapi/api/v1/chat/completions
Accept: text/event-stream
Content-Type: application/json
```

模型目录：

```text
GET /superCowork/sapi/api/v1/model-options?language=zh-CN
```

上游成功响应是 SSE。Chat Completions 流式请求直接转发 `data:` 和 `[DONE]`。其他请求由网关读取 SSE，按索引合并工具调用增量，并生成对应协议的事件或 JSON。

## 安全边界

- 只监听 `127.0.0.1` 或 `localhost`。
- 不代发短信、不复现 `open.e.189.cn` 登录。
- 不从安装包提取内置占位 key。
- 凭据只留在用户本机。
- 请求体上限为 8 MiB。

协议和验证细节见 `ANALYSIS.md`。
