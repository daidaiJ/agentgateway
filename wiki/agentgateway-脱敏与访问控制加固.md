# agentgateway 脱敏与访问控制加固笔记

**日期：** 2026-10-28
**范围：** agentgateway（`D:\pro\agentgateway`，commit `cfa8d1b`）的 LLM/MCP 脱敏（prompt guardrails）配置、其与本地网关 magpie（`D:\pro\magpie`）脱敏机制的关系、以及非回环匿名访问的补强方案。
**依据：** 仓库源码、`schema/config.md`、`schema/config.json`、`examples/` 下的官方示例；magpie 的 `internal/redact`、`docs/subsystems/`。所有配置片段都用仓库 `schema/config.json` 做过 JSON Schema 校验。
**用途约束：** 本文用于判断配置方式和选型边界。除特别说明外，行为结论来自读源码与单测断言，**未启动网关实跑流量**；见文末「验证状态」。

---

## 0. 执行摘要

1. **脱敏**在 agentgateway 里是 LLM/MCP 策略，配置入口是 `policies.ai.promptGuard` 与 `policies.mcpGuardrails`；替换是**单向不可逆**的固定占位符（`<EMAIL_ADDRESS>`、`<masked>`），网关不保存原值映射。
2. **magpie 的脱敏是可逆的**：出站把密钥/个人信息/自定义词换成 `{{KIND_hash8}}` 占位符，入站再还原（含流式），厂商侧永远拿不到明文。两者方向相反、层次不同，**互补而非替代**，但**不能直接对接**（magpie 不提供 guardrail webhook 契约）。
3. **非回环匿名访问**不是漏洞而是配置责任：省略 `bindAddress` 时监听所有接口，未配认证策略的路由放行匿名请求，只有 admin UI 默认绑回环。补强按三层做：网关内建（`networkAuthorization` + `jwtAuth`/`apiKey` + `authorization` + `localRateLimit`）、Envoy 生态（ext_authz/ext_proc/RLS：oauth2-proxy、Tailscale whois、OPA/AuthZEN、Keycloak）、部署边界（只绑内网、NetworkPolicy、SPIFFE、零信任网络）。

---

## 1. agentgateway 的脱敏怎么配

### 1.1 配置位置

- LLM：`binds[].listeners[].routes[].policies.ai.promptGuard`，或 backend 级 `...backends[].ai.policies.ai.promptGuard`。
- MCP：`binds[].listeners[].routes[].policies.mcpGuardrails.processors`（或 `mcp.policies.mcpGuardrails`）。

### 1.2 机制要点

| 项 | 行为 |
| --- | --- |
| 动作 | `regex.action` 取 `mask` / `reject` / `audit`，默认 `mask` |
| 内置识别器 | `ssn`、`creditCard`、`phoneNumber`、`email`、`caSin`；占位符用识别器给的实体类型，如 `<EMAIL_ADDRESS>`、`<CREDIT_CARD>`、`<SSN>`、`<PHONE_NUMBER>`（`crates/agentgateway/src/llm/policy/mod.rs:1873`） |
| 自定义正则 | `rules[].pattern`，替换文本固定为 `<masked>`（同文件 `:1928`） |
| scope | request 默认 `systemPrompt + messages + toolOutput`；response 默认 `messages`；可加 `toolInput`，但 Completions 这类把工具参数当不透明 JSON 的 API 会把参数当整串掩码，可能改成非法 JSON |
| 流式 | `streaming: Enabled` 逐事件处理 SSE / 实时 websocket；签名响应会被扫描，掩码若会改变签名则改为 reject |
| 外部守卫 | `webhook` / `openAIModeration` / `bedrockGuardrails` / `googleModelArmor` / `azureContentSafety` 负责判定，网关决定是否执行（`action: reject \| audit`，默认 reject；`failureMode` 默认 failClosed）。Bedrock 的 `ANONYMIZED` 评估会掩码 |
| 自建 DLP 入口 | webhook 守卫协议为 `POST /request`、`POST /response`，可返回 `mask` 动作替换 prompt/response 正文（`crates/agentgateway/src/llm/policy/webhook.rs` 的 `MaskAction`） |
| MCP 脱敏 | `mcpGuardrails.processors` 的 `kind: expression` 用 CEL 的 `regexReplaceAll` / `regexReplace` 重写 `mcp.params`（请求侧）或 `mcp.result`（响应侧）；`kind: remote` 交给外部策略服务；`methods: {"tools/call": request}` 精确到方法与阶段 |
| 日志侧 | `config.sensitiveHeaders` 从 trace/debug 抹掉指定头；CEL 有 `request.headers.redacted()`；`jwt.rawToken`、`apiKey.key` 默认脱敏，取原值须 `.unredacted()`；`guardrails[].assessments` 只含元数据，不含匹配文本；指标 `agentgateway_guardrail_checks_total` |

### 1.3 LLM 脱敏（schema 校验通过）

```yaml
binds:
- port: 3000
  listeners:
  - routes:
    - policies:
        ai:
          promptGuard:
            streaming: Enabled
            request:
            - regex:
                action: mask
                rules:
                - builtin: email
                - builtin: creditCard
                - builtin: ssn
                - builtin: phoneNumber
                - builtin: caSin
                - pattern: 'AKIA[0-9A-Z]{16}'
              scope: [systemPrompt, messages, toolOutput, toolInput]
            - regex:
                action: audit
                rules:
                - pattern: '(?i)internal-only'
            response:
            - regex:
                action: mask
                rules:
                - builtin: email
              scope: [messages]
      backends:
      - ai:
          name: openai
          provider: { openAI: { model: gpt-4o-mini } }
```

### 1.4 MCP 工具调用脱敏（schema 校验通过）

```yaml
mcp:
  policies:
    mcpGuardrails:
      processors:
      - kind: expression
        methods: {"tools/call": request}
        condition: has(mcp.params.arguments)
        transform: >-
          mcp.params.with(p, p.merge({'arguments': p.arguments.merge({
            'note': p.arguments.note.regexReplaceAll('[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+[.][A-Za-z]{2,}', '[EMAIL]')
          })}))
      - kind: expression
        methods: {"tools/call": response}
        condition: has(mcp.result.content)
        transform: >-
          mcp.result.with(r, r.merge({'content': r.content.map(item,
            item.type == 'text' ? item.merge({'text': item.text.regexReplaceAll('AKIA[0-9A-Z]{16}', '[AWS_KEY]')}) : item)}))
```

---

## 2. 与 magpie 脱敏的关系：互补

### 2.1 magpie 机制（`internal/redact`、`internal/gateway/redact.go`）

- 占位符形如 `{{API_KEY_k3v9x2mq}}`，由 HMAC 派生（密钥 `redact.key`），**同一个值恒定同一占位符**，所以对话历史、厂商侧缓存、thinking 签名仍然对得上；明文只留内存。
- 出站 `redact.MaskJSON`（请求体）与 `redact.Mask`（图片/视频 prompt）；入站 `redact.Writer` 逐事件还原，能处理跨事件拆开的占位符与模型改写过的形态。
- 覆盖面比 agentgateway 宽：secrets 含私钥、各厂商 API key、JWT、连接串密码、`KEY=...` 赋值式密钥；personal 默认开 US SSN、护照号、过 mod 97 的 IBAN、紧跟日期词的生日、MAC、S/N 序列号，默认关 home 目录用户名、`user@host`、公网 IP、bucket 名；再加用户自定义词与规则（kind + prefix 或 RE2）。
- 不改工具定义与输出 schema（只改其中的 description），签名/加密块原样回传；日志、归档、最近调用、OTel 请求响应体走同一套 scrub。
- 每个 provider 可勾 "Send requests unmasked"（`provider.SkipsRedaction`），仅当所有地址都在本机/局域网时生效；签入账号、插件 provider、远端 magpie 永远掩码。

### 2.2 对比

| 维度 | agentgateway | magpie |
| --- | --- | --- |
| 方向 | 单向不可逆，不持有映射表 | 可逆，明文映射表在本机内存 + `redact.key` |
| 位置 | 集群/共享网关入口，覆盖所有客户端与多租户身份 | 单台开发机，agent ↔ 厂商之间 |
| 覆盖 | LLM 请求/响应 + MCP 工具调用 + 流式 | LLM 请求/响应与流（不代理 MCP） |
| 能力 | 阻断、audit 观测、指标、自定义拒绝响应、外部 DLP 接入 | 保留 agent 可用性的保密（路径、URL、命令里仍能用真值） |
| 识别库 | 5 类内置 + 自定义正则 + 外部 DLP 判定 | 密钥类与上下文规则更宽 |

### 2.3 组合建议与注意点

- 组合方式：集群侧 agentgateway 做强制边界（关键密钥 `reject`、PII `mask`、其余 `audit`、MCP 工具参数脱敏），本机 magpie 让 agent 在真值下正常工作。
- 不能在 agentgateway 里直接调用 magpie 当守卫：magpie 不实现 `POST /request`、`POST /response` 那套契约。要在 agentgateway 侧接自建 DLP，用 webhook 守卫 + `mask` 动作。
- agentgateway 掩码不可逆，模型与客户端都拿不到原值，"帮我写一封发给某邮箱的邮件"这类任务会退化；`toolInput` 掩码可能破坏 JSON；签名响应被掩码会被改成 reject。
- magpie 的可逆意味着本机一旦被攻破，`redact.key` 加内存映射即可还原；它也没有策略式阻断与审计分级。

---

## 3. 非回环匿名访问的补强

### 3.1 前提（读源码确认的默认值）

| 事实 | 依据 |
| --- | --- |
| `bindAddress` 省略时监听所有接口（`::` / `0.0.0.0`） | `crates/agentgateway/src/types/local.rs:1158`、`:3802` |
| 未配认证策略的路由放行匿名请求 | `crates/agentgateway/src/http/authorization.rs`，`RuleSets::validate`：无规则集即全员可访问 |
| 只有 admin UI 默认绑回环 `localhost:15000`，可设 `off` | `crates/agentgateway/src/config.rs:355` |

### 3.2 第一层：网关内建

连接层直接拒绝非回环/非内网来源（schema 校验通过）：

```yaml
config:
  adminAddr: "localhost:15000"
frontendPolicies:
  networkAuthorization:
    rules:
    - require: >-
        ip(source.address).isLoopback() ||
        cidr("10.0.0.0/8").containsIP(ip(source.address)) ||
        cidr("192.168.0.0/16").containsIP(ip(source.address))
```

该表达式与代码库自己生成网络授权规则的写法一致（`crates/agentgateway/src/store/binds.rs:2895` 用 `cidr("...").containsIP(source.address)`）；`networkAuthorization` 的求值走 TCP executor（`crates/agentgateway/src/proxy/gateway.rs:916`），`source.address` 在该上下文可用。

请求层与身份层（schema 校验通过）：

```yaml
binds:
- port: 3000
  listeners:
  - name: llm
    protocol: HTTP
    policies:
      jwtAuth:
        mode: strict
        providers:
        - issuer: https://keycloak.example.com/realms/agents
          audiences: [agentgateway]
          jwks:
            url: https://keycloak.example.com/realms/agents/protocol/openid-connect/certs
      authorization:
        rules:
        - require: 'jwt.sub != ""'
    routes:
    - policies:
        authorization:
          rules:
          - allow: 'jwt.claims.scope.contains("llm:invoke")'
        localRateLimit:
        - maxTokens: 60
          tokensPerFill: 60
          fillInterval: 1m
          key: 'jwt.sub'
      backends:
      - ai:
          name: openai
          provider: { openAI: { model: gpt-4o-mini } }
```

其它可选项：

| 能力 | 配置键 | 关键点 |
| --- | --- | --- |
| API Key | `apiKey`（`mode: strict`，`keys[].keyHash: sha256:...`） | 支持 `allowedModels` 与 USD/Token 预算（`onBudgetExceeded: Block`） |
| 外部授权 | `extAuthz`（gRPC 或 HTTP，Envoy ext_authz 兼容） | `failureMode.denyWithStatus` 要显式设 |
| 浏览器登录 | `oidc`（授权码流 + 会话 Cookie）、`ui.policies.oidc` | 官方示例 `examples/traffic-oidc` |
| MCP 面 | `mcpAuthentication`（OAuth 资源服务器，预设 auth0/keycloak/okta/descope/authentik/entra）+ `mcpAuthorization` | 官方示例 `mcp-authentication`、`mcp-authorization`、`mcp-authzen` |
| 传输层身份 | listener `tls.root`（mTLS 客户端证书）、`tls.spiffe`（SPIRE） | `source.identity.*`、`source.spiffeId` 可进 CEL |
| 限流 | `localRateLimit`（按 requests 或 tokens）、`remoteRateLimit`（Envoy RLS） | 跨实例配额用后者 + envoyproxy/ratelimit |

### 3.3 第二层：Envoy 生态直接可插

agentgateway 实现了 Envoy 的 ext_authz（gRPC + HTTP）、ext_proc 和 RLS，下列现成方案不用改造即可接：

1. **oauth2-proxy** — 官方示例 `examples/traffic-oauth2-proxy`：forward-auth 到 `/oauth2/auth`，失败重定向 `/oauth2/start?rd=`，身份经 `x-auth-request-user` 回注并进访问日志（schema 校验通过）：

```yaml
binds:
- port: 3000
  listeners:
  - name: llm
    protocol: HTTPS
    tls:
      cert: /etc/tls/tls.crt
      key: /etc/tls/tls.key
      root: /etc/tls/client-ca.crt
    routes:
    - policies:
        extAuthz:
          host: oauth2-proxy.auth.svc.cluster.local:4180
          includeRequestHeaders: [cookie, authorization]
          protocol:
            http:
              path: '"/oauth2/auth"'
              redirect: '"/oauth2/start?rd=" + request.pathAndQuery'
          failureMode:
            denyWithStatus: 403
      backends:
      - ai:
          name: openai
          provider: { openAI: { model: gpt-4o-mini } }
```

2. **Tailscale whois** — 官方示例 `examples/traffic-tailscale-auth`：`host: unix:/run/tailscale/tailscaled.sock`，用 `"/localapi/v0/whois?addr=" + source.address` 把访问权收敛到 tailnet 身份，不需要中间组件。
3. **OPA / AuthZEN 外部授权** — 官方示例 `examples/mcp-authzen`（Keycloak + AuthZEN PDP + RFC 8693 令牌交换）。
4. **Keycloak / Authentik / Authelia / Pomerium / Cloudflare Access** — 任何提供 OIDC 或 ext_authz 的都能接。
5. **限流与 WAF** — envoyproxy/ratelimit 走 `remoteRateLimit`（示例 `traffic-ratelimiting-global`）；Coraza/ModSecurity 类走 `extProc`。

需要按条件选择授权服务时，用条件式写法（schema 校验通过）：

```yaml
services:
- name: oauth2-proxy
  namespace: auth
  hostname: oauth2-proxy.auth.svc.cluster.local
  ports:
    4180: 4180
binds:
- port: 3000
  listeners:
  - name: llm
    protocol: HTTPS
    tls:
      cert: /etc/tls/tls.crt
      key: /etc/tls/tls.key
      root: /etc/tls/client-ca.crt
    routes:
    - policies:
        extAuthz:
          conditional:
          - service:
              name: oauth2-proxy
              port: 4180
            protocol:
              http:
                path: '"/oauth2/auth"'
                redirect: '"/oauth2/start?rd=" + request.pathAndQuery'
            failureMode:
              denyWithStatus: 403
        remoteRateLimit:
          conditional:
          - domain: agentgateway
            service:
              name: ratelimit
              port: 8081
            descriptors:
            - entries:
              - key: user
                value: 'jwt.sub'
      backends:
      - ai:
          name: openai
          provider: { openAI: { model: gpt-4o-mini } }
```

### 3.4 第三层：部署边界

- 只绑内网地址（`bindAddress`），公网入口交给会终止认证的组件（nginx `auth_request`、Traefik `forwardAuth`、Envoy Gateway、Istio AuthorizationPolicy + ambient mTLS）。
- Kubernetes：NetworkPolicy 限制谁能到 gateway Pod；Gateway API + agentgateway 自己的 CRD（`agentgateway.dev` 组的 `AgentgatewayPolicy`：`spec.frontend.networkAuthorization`、`spec.frontend.tls`、`spec.traffic.extAuth/rateLimit/cors/csrf`）；工作负载身份用 SPIFFE/SPIRE（示例 `traffic-spiffe`）。注意 Istio 的 `PeerAuthentication` 在该 controller 里是 disabled collection（`controller/pkg/syncer/syncer.go:882`），别指望它生效。
- 零信任网络：Tailscale / NetBird（示例 `netbird-agent-network`）/ Cloudflare Tunnel。
- 设备合规：示例 `microsoft-intune`。

### 3.5 落地顺序

1. 现在：`frontendPolicies.networkAuthorization` 只放回环 + 内网 CIDR；`adminAddr` 保持回环或设 `off`。
2. 这周：所有 LLM/MCP 路由加 `jwtAuth`（或 `apiKey` + `keyHash`）、`authorization` 用 allow 白名单、加 `localRateLimit`。
3. 需要统一身份/浏览器登录时上 `oidc` 或 extAuthz + oauth2-proxy/Keycloak；需要跨实例配额时上 `remoteRateLimit` + envoyproxy/ratelimit。

### 3.6 易踩的坑

- `authorization` 只写 `deny` 规则时是黑名单语义（默认放行）；要默认拒绝必须至少有一条 `allow` 规则或用 `require`。
- `apiKey.keys[].key` 是明文，配置里应使用 `keyHash`。
- `extAuthz` 的 `failureMode` 不显式设 `denyWithStatus` 时行为取决于默认值，认证服务宕机会放大风险。
- CIDR 白名单表达的是网络位置而非身份，挡不住内网横向与 SSRF，要和身份层叠加。
- listener 只配服务器证书时客户端仍是匿名，要 mTLS 必须配 `tls.root`。

---

## 4. 验证状态

已验证：

- 本文所有 YAML 片段都用仓库 `schema/config.json`（JSON Schema 2020-12，`jsonschema 4.26.0`）校验通过。
- CEL 用到的 `ip()`、`cidr().containsIP()`、`isLoopback()` 在 `crates/celx/src/cidr.rs` 有注册，在 `crates/celx/src/function_tests.rs` 有单测。
- 占位符文本（`<EMAIL_ADDRESS>` 等）来自 `crates/agentgateway/src/llm/policy/mod.rs` 与其单测断言。
- magpie 行为来自 `internal/redact/*.go`、`internal/gateway/redact.go`、`internal/provider/unredacted.go` 与 `docs/subsystems/gateway-routing.md`。

未验证：

- 未启动网关实跑流量（仓库无预编译二进制，全量 Rust 构建成本高）。因此"掩码后的实际上游报文""非回环请求被 403"属于静态推断。要坐实：`cargo run -- -f <配置>` 后发一条含邮箱的 `/v1/chat/completions` 看上游是否收到 `<EMAIL_ADDRESS>`；用 `curl --interface <非回环地址>` 打一条请求看是否 403。
- 条件式 `extAuthz` / `remoteRateLimit` 里的 `services` 条目在 schema 中是开放对象（`additionalProperties: true`），字段形状取自 `Service` 类型定义，未经运行时验证。
