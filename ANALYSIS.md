# TeleAgent 协议分析

分析对象是本机安装的 TeleAgent 3.0.0-rc.1。结论来自安装包静态分析、IDA 反编译、本机运行时长度核对，以及 Linux 与 Windows 上的真实请求。分析过程没有保存 token、会话密钥、签名或消息正文。

## 1. 登录

网页版和桌面版不是同一条凭据链路。

网页登录成功后停在：

```text
https://agent.teleai.com.cn/teleagent
```

会话位于域 `teleai.com.cn` 的 Cookie `operationToken`，同值还有 `x-token`。它不会出现在回跳 URL 中，`localhost` 页面也读不到这个跨域 Cookie。

桌面版登录窗才会监听：

```text
/superCowork/sapi/cowork/auth?code=...&token=...
```

`code` 只是成功标志，真正使用的是 `token`。桌面程序随后把它保存为本机加密状态，不写进普通日志。

因此网关不做浏览器回跳粘贴，也不实现短信登录。它要求 TeleAgent 已经在当前平台完成登录。

## 2. 身份校验与模型目录

只带 `X-Token` 即可访问：

```text
GET /superCowork/sapi/cowork/user_info
GET /superCowork/sapi/api/v1/model-options?language=zh-CN
```

`user_info` 返回 HTTP 200、业务码 200。顶层字段为 `code`、`data`、`msg`；`data` 包含 `accountId`、`userId`、`accountName`、`userName`、`phone`、`avatar`、`certificationType`。

模型目录返回 HTTP 200、业务码 0。实测模型为：

- `chat-pro`
- `chat-flagship`
- `chat-flash`

模型字段包括 `model`、`category`、`category_name`、`display_name`、`is_default`、`icon`、`tags`、`options`、`context_limit`、`description`、`points_multiplier`。

直接调用 `/api/v1/chat/completions` 只带 `X-Token` 时返回 HTTP 401。缺少签名时业务码是 `40101`；签名不正确时业务码是 `40104`。

## 3. 官方对话链路

网页和 WSL 客户端都不由页面直接构造最终模型请求。

1. 页面调用本地 AIS 的 `SessionService/SendMessage`。
2. AIS 请求 `POST /api/v1/check/content`，场景先是 `user_input`，回复后是 `assistant_output`。
3. AIS 再调用本地运行时 `POST /session/<id>/prompt_async`，成功返回 HTTP 204。
4. 本地运行时签名并请求云端 `/api/v1/chat/completions`。
5. 用量记录中的 provider 为 `NewApi`，本次测试模型为 `chat-pro`。

WSL 本地运行时端口在不同启动中出现过 `4397`、`4398` 和 `46001`。端口不是协议的一部分，网关不依赖本地运行时代发。

## 4. 签名

IDA 中的函数是 `GatewaySigner.Sign`，入口地址 `0x117c380`。`hmacHex` 位于 `0x117e800`，固定调用：

```text
crypto/hmac.New(crypto/sha256.New, key)
```

输出使用 `0123456789abcdef`，因此是小写十六进制。

调用方 `SuperAgentTransport.RoundTrip` 先计算请求体摘要：

```text
bodyHash = hex(SHA-256(rawBody))
```

然后调用签名函数。真实请求的长度核对证明签名串最后一项是这个 64 字符摘要，不是原始 body，也不是第一段 HMAC。

设 JWT 按 `.` 分成三段时，HMAC 第一段密钥取第三段；否则使用整个 Token。

```text
payloadHash = hex(HMAC_SHA256(jwtThirdSegment(Token),
  join([
    "superagent-auth-v1",
    Token,
    InstallID,
    timestamp,
    nonce
  ], "/")))

signature = hex(HMAC_SHA256(payloadHash,
  join([
    "superagent-auth-v1",
    upper(method),
    requestURI,
    timestamp,
    nonce,
    appVersion,
    bodyHash
  ], "\n")))
```

真实对话中观察到的长度包括：

```text
5 项：18, 646, 36, 10, 36
7 项：18, 4, 41, 10, 36, 10, 64
```

对应关系是：

| 长度 | 含义 |
|---|---|
| 18 | `superagent-auth-v1` |
| 646 | 本次登录 Token |
| 36 | Install ID |
| 10 | Unix 秒级 timestamp 或 nonce |
| 4 | `POST` |
| 41 | `/superCowork/sapi/api/v1/chat/completions` |
| 64 | SHA-256 或 HMAC 的十六进制结果 |

早期反编译曾把 `rawBody`、`appVersion` 和 `nonce` 的位置解释错。最终以真实请求长度和上游 HTTP 200 为准。

## 5. 请求头

```text
X-Token: <Token>
X-SuperAgent-Timestamp: <timestamp>
X-SuperAgent-Nonce: <nonce>
X-SuperAgent-Device-Id: <DeviceID，可省略>
X-SuperAgent-Install-Id: <InstallID，可省略>
X-SuperAgent-Sign-Version: v1
X-SuperAgent-Signature: <signature>
X-App-Version: 3.0.0-rc.1
Content-Type: application/json
Accept: text/event-stream
```

网关另外附带 `X-Timestamp`、`X-Nonce`、`X-OS-Type`、`X-Device-Os` 和 `X-Teleai-Client-Type`。模型请求不使用网页登录阶段的 `Authorization: Bearer` 占位值。

## 6. 请求体与响应

`buildChatBody` 生成 OpenAI 兼容 JSON：

```json
{
  "model": "chat-pro",
  "messages": [
    {"role": "system", "content": "..."},
    {"role": "user", "content": [{"type": "text", "text": "..."}]}
  ],
  "stream": true,
  "max_tokens": 65536
}
```

规则：

- 只有系统提示存在时才写 `system`。
- 普通文本转换成 `[{"type":"text","text":"..."}]`。
- 图片使用 `image_url`。
- 有工具才写 OpenAI function `tools`。
- `max_tokens` 仅在大于 0 时写入；官方客户端记录为 65536。
- 只有模型能力允许时才写 `temperature`。
- 推理模型才写 `reasoning_effort` 和 `thinking`。
- `chat-pro` 支持工具调用，不支持温度、推理和附件。

成功响应为 `text/event-stream`。客户端按 `data:` 分行，忽略空行、注释和结束标记 `[DONE]`。

它读取：

- `choices[0].delta.content`
- `choices[0].delta.reasoning_content`
- `choices[0].delta.tool_calls`，按 `index` 合并 `id`、`type`、`function.name`、`function.arguments`
- `model`
- `usage.prompt_tokens`、`completion_tokens`、`total_tokens`、`cached_tokens`

非 SSE JSON 则读取 `choices[0].message.content` 和 `tool_calls`。HTTP 非 200 直接返回状态码。

## 7. 本机登录态

`AuthState` 只有三个字段：

```json
{"token":"...","deviceId":"...","installId":"..."}
```

设备标识位于：

```text
~/.local/share/TeleAgent/app-auth/device-meta.json
```

Linux 的 token 文件使用 `scheme=local`。同目录 `local-key` 提供 32 字节 AES 密钥，密文是 AES-256-GCM。前 12 字节是 nonce，随后 16 字节是 tag，剩余部分是 ciphertext。

Windows 文件使用 `scheme=safe_storage`。客户端通过 Electron `safeStorage` 调用当前用户的 DPAPI，不存在可直接复用的 `local-key`。因此 Windows 零配置必须在该 Windows 用户自己的进程里完成，不能从 WSL 或另一台机器解密。

`auth.json` 保存的是模型 provider 配置，不是这三个登录字段。

## 8. 实测

Linux 网关 `127.0.0.1:8787`：

- `/health`、`/v1/models` 返回 HTTP 200。
- `chat-pro`、`chat-flash`、`chat-flagship` 均返回 `pong`，`finish_reason=stop`。
- 流式响应有 60 个 SSE 分片、`usage` 和 `[DONE]`。
- 工具调用返回 `finish_reason=tool_calls`，函数名为 `get_weather`。
- 回传工具结果后，回复包含 `18` 和 `cloudy`。
- 空请求返回 HTTP 400。

Windows 在本机 Windows 进程内使用 DPAPI 做了同样的接口测试，结果相同。随后把 DPAPI 调用放进仓库的独立 PowerShell 路径时解密失败，所以文档不把它记为已经稳定的 Windows 零配置实现。

## 9. 仍有的限制

- `stream:false` 没有在网关内聚合成 JSON。
- Windows 独立进程的 DPAPI 解密还需在 Windows 上继续复核。
- 官方客户端版本升级后，签名字段顺序和登录文件格式都需要重新验证。
