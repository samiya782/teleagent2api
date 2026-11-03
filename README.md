# teleagent2api

把本机已经登录的 TeleAgent 3.0.0-rc.1 转成只监听本机的 OpenAI 兼容网关。

它不实现天翼账号登录，也不接收手机号或验证码。程序只读取当前平台上 TeleAgent 已保存的登录状态，并代发官方模型请求。

## 当前状态

| 平台 | 零配置 | 实测 |
|---|---|---|
| Linux / WSL | 可以。读取 `local-key` 与 `token.json` | `/health`、模型列表、流式对话、三个模型、工具调用及工具结果回传通过 |
| Windows | 代码会查找本机登录文件并尝试 DPAPI | 在 Windows 进程内做过完整接口测试并通过；仓库里的独立 DPAPI 解密路径尚未复核成功，不能视为稳定零配置 |

`stream:false` 当前仍透传上游 SSE，不会聚合成单个 JSON。

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
```

Windows 的 `scheme=safe_storage` 不使用 Linux 的 `local-key`。它必须由同一个 Windows 用户进程通过 DPAPI 解密。

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
| GET | `/v1/models` | 转发模型目录 |
| POST | `/v1/chat/completions` | OpenAI 兼容对话 |

对话示例：

```bash
curl http://127.0.0.1:8787/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"chat-pro","stream":true,"messages":[{"role":"user","content":"Reply with pong only."}]}'
```

支持 `messages`、文本数组、`tools`、`tool_choice`、`tool_calls` 和工具结果回传。`chat-pro` 实测不支持温度、推理和附件，但支持工具调用。可用模型为 `chat-pro`、`chat-flagship`、`chat-flash`。

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

成功响应是 SSE。网关转发 `data:` 行，保留 `[DONE]`，忽略空行和注释。增量字段包括 `delta.content`、`delta.reasoning_content`、按 index 合并的 `tool_calls`，以及 `usage`。

## 安全边界

- 只监听 `127.0.0.1` 或 `localhost`。
- 不代发短信、不复现 `open.e.189.cn` 登录。
- 不从安装包提取内置占位 key。
- 凭据只留在用户本机。
- 请求体上限为 8 MiB。

协议和验证细节见 `ANALYSIS.md`。
