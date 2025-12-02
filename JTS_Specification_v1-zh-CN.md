
# 项目归档文档：Janus 令牌系统 (JTS)

**标题：** Janus 令牌系统 (JTS)：一个用于安全、可撤销和机密 API 身份验证的双组件架构

**状态：** 标准草案，版本 1.1

**作者/先驱：** ukungzulfah

**发布日期：** 2025年11月30日

> **摘要：**
> 本文档定义了 **Janus 令牌系统 (JTS)**，这是一种新的身份验证标准，旨在解决现代分布式应用生态系统（例如，微服务架构）中的安全性和可伸缩性挑战。JTS 引入了一个双组件架构，从根本上将 **短期访问凭证 (`BearerPass`)** 与 **长期会话凭证 (`StateProof`)** 分离开来。这种方法在保留包括即时会话撤销在内的 *有状态* 会话管理的关键能力的同时，实现了极速且 *无状态* 的访问验证。本文档定义了三种操作配置文件：**JTS-S (标准)** 用于具有完整安全功能的完全完整性，**JTS-L (轻量级)** 用于复杂性最低的轻量级实现，以及 **JTS-C (机密性)** 用于完全的有效负载机密性。本规范还引入了新的声明术语，以取代不太直观的传统术语。

---

### **版权许可**
> 版权所有 © 2025, ukungzulfah。保留所有权利。
>
> 特此免费授予任何获得本规范及相关文档（“本软件”）副本的人员使用、复制、修改、合并、发布、分发和/或销售本软件副本的许可，但需遵守以下条件：
>
> 上述版权声明和本许可声明应包含在本软件的所有副本或主要部分中。本软件按“原样”提供，不作任何明示或暗示的保证。

---

### **1. 引言**

#### **1.1. 现代身份验证挑战**
在现代软件架构中，应用程序被分解为小型的、独立的服务（微服务）。这种模型要求身份验证系统轻量、去中心化，并且不依赖于单一的、庞大的集中式会话。

#### **1.2. 早期无状态令牌模型的局限性**
第一代基于无状态令牌的身份验证模型提供了部分解决方案，但引入了重大弱点：
1.  **会话撤销漏洞：** 已发布的令牌在过期前无法从服务器端强制失效。
2.  **信息暴露：** 令牌的有效负载通常只是编码而非加密，因此持有令牌的任何一方都可以读取其中的数据。
3.  **密钥管理复杂性：** 在分布式环境中使用共享对称密钥会产生高风险的单点故障。

#### **1.3. 新范式：Janus 令牌系统 (JTS)**
JTS 被提议作为解决这些弱点的演进方案。凭借其二元性原则，JTS 将 *无状态* 的效率与 *有状态* 的安全性结合起来。

### **2. JTS 核心概念**

#### **2.1. 二元性原则**
JTS 将令牌的角色分为两个：
1.  **访问：** 在极短时间内授予访问资源的权限。
2.  **会话：** 证明用户整个身份验证会话的有效性。

#### **2.2. JTS 的两个组件**
1.  **`BearerPass`：** 一个经过加密签名的、短期的访问令牌。它用于每个 API 请求中，并以无状态方式进行验证。
2.  **`StateProof`：** 一个不透明且有状态的、长期的会话令牌。它专门用于获取新的 `BearerPass`，并安全地存储在客户端。它在服务器数据库中的存在决定了会话的有效性。

### **3. JTS 术语和声明**

作为一种改进，JTS 引入了更明确、更直观的声明术语，摒弃了模糊的传统术语。

| JTS 声明 | 全名 | 描述 | 替代 |
| :--- | :--- | :--- | :--- |
| **`prn`** | **Principal** | 经过身份验证的主体（通常是用户）的唯一标识符。 | `sub` |
| **`aid`** | **Anchor ID** | 将 `BearerPass` “锚定”到服务器上会话记录的唯一 ID。 | `sid` |
| **`tkn_id`**| **Token ID** | 每个 `BearerPass` 的唯一标识符，防止重放攻击。 | `jti` |
| `exp` | Expiration Time | 令牌过期时间（保留自 RFC 7519）。 | - |
| `aud` | Audience | 此令牌的目标接收方（保留自 RFC 7519）。 | - |
| `iat` | Issued At | 令牌颁发时间（保留自 RFC 7519）。 | - |

#### **3.2. 扩展声明**

JTS 定义了额外的声明，以实现更强大的安全性和功能性：

| JTS 声明 | 全名 | 描述 | 必需 |
| :--- | :--- | :--- | :--- |
| **`dfp`** | **Device Fingerprint** | 用于将令牌绑定到特定设备的设备特征哈希。 | 否 |
| **`perm`**| **Permissions** | 定义令牌所持有的权限/范围的字符串数组。 | 否 |
| **`grc`** | **Grace Period** | `exp` 之后为处理中的请求提供的时间容差（秒）。 | 否 |
| **`org`** | **Organization** | 多租户系统的租户/组织标识符。 | 否 |
| **`atm`** | **Auth Method** | 使用的身份验证方法（例如 `pwd`, `mfa:totp`, `sso`）。 | 否 |
| **`ath`** | **Auth Time** | 用户上次执行主动身份验证的 Unix 时间戳。 | 否 |
| **`spl`** | **Session Policy** | 生效的并发会话策略（`allow_all`, `single`, `max:n`）。 | 否 |

**带扩展声明的示例有效负载：**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400,
  "dfp": "sha256:a1b2c3d4e5f6...",
  "perm": ["read:profile", "write:posts", "billing:view"],
  "grc": 30,
  "org": "tenant-acme-corp",
  "atm": "mfa:totp",
  "ath": 1764512000
}
```

### **4. 标准配置文件：JTS-S (完整性)**

此配置文件侧重于速度、完整性和会话撤销能力。

#### **4.1. `BearerPass` 结构 (JWS 格式)**
JTS-S 配置文件中的 `BearerPass` 是一个使用 **非对称加密（例如 RS256）** 签名的 **JSON Web Signature (JWS)**。

**示例头部：**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**注意：** `kid` (Key ID) 声明是强制性的，以支持密钥轮换（见第 7 节）。

**示例有效负载：**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "tkn_id": "token-instance-98765",
  "aud": "https://api.example.com/billing",
  "exp": 1764515700,
  "iat": 1764515400
}
```

#### **4.2. 工作流程**
1.  **身份验证：** 用户登录 -> 服务器在数据库中创建会话记录，生成一个 `StateProof`（存储在数据库中）和一个 `BearerPass` (JWS)。`StateProof` 通过 `HttpOnly` cookie 发送，`BearerPass` 通过 JSON 正文发送。
2.  **资源访问：** 客户端在头部发送 `BearerPass` -> 服务器使用公钥验证 JWS 签名。
3.  **续订：** `BearerPass` 过期 -> 客户端使用 cookie 中的 `StateProof` 调用 `/renew` 端点 -> 服务器在数据库中验证 `StateProof`；如果有效，则颁发一个新的 `BearerPass`。
4.  **撤销 (登出)：** 客户端调用 `/logout` -> 服务器从数据库中删除与 `StateProof` 关联的会话记录。会话立即失效。

#### **4.3. Cookie 要求和 CSRF 保护**

存储在 cookie 中的 `StateProof` 必须满足以下安全要求：

**强制性 Cookie 属性：**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| 属性 | 值 | 描述 |
| :--- | :--- | :--- |
| `HttpOnly` | 强制性 | 防止 JavaScript 访问（缓解 XSS）。 |
| `Secure` | 强制性 | Cookie 仅通过 HTTPS 发送。 |
| `SameSite` | `Strict` | 防止在跨站请求中发送 cookie（缓解 CSRF）。 |
| `Path` | `/jts` | 限制 cookie 仅发送到 JTS 端点。 |
| `Max-Age` | 根据策略 | Cookie 生命周期根据会话策略确定。 |

**额外的 CSRF 保护：**

对于 `/renew` 和 `/logout` 端点，服务器必须验证以下至少一种机制：

1.  **Origin 头部验证：** 确保 `Origin` 或 `Referer` 头部来自允许的域。
2.  **自定义头部要求：** 要求一个无法通过标准表单提交设置的自定义头部：
    ```
    X-JTS-Request: 1
    ```
3.  **双重提交 Cookie 模式：** 在 cookie 和请求正文/头部中都发送一个 CSRF 令牌值，然后验证它们是否匹配。

#### **4.4. StateProof 轮换**

为了增强安全性并检测令牌盗窃，JTS 要求在每次续订操作时轮换 `StateProof`。

**机制：**
1.  客户端使用旧的 `StateProof` 调用 `/renew`。
2.  服务器在数据库中验证旧的 `StateProof`。
3.  如果有效：
    a.  服务器删除或标记旧的 `StateProof` 为 *已消耗*。
    b.  服务器颁发一个新的 `StateProof` 和一个新的 `BearerPass`。
    c.  新的 `StateProof` 通过 `Set-Cookie` 头部发送。
4.  如果旧的 `StateProof` 已被标记为 *已消耗*（检测到重放）：
    a.  服务器必须立即撤销与该 `aid` 关联的所有会话。
    b.  服务器必须返回一个 `JTS-401-05` (会话被盗) 错误。
    c.  服务器应向用户发送安全通知。

**轮换图：**
```
[客户端]                              [认证服务器]                    [数据库]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- 验证 StateProof_v1 ---->|
    |                                       |<-- 有效, 标记为已消耗 ---|
    |                                       |                               |
    |                                       |-- 生成 StateProof_v2 ---->|
    |                                       |<-- 已存储 --------------------|
    |                                       |                               |
    |<-- 200 OK (BearerPass_new) -----------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**异常检测 (重放攻击)：**
```
[攻击者]                            [认证服务器]                    [数据库]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (被盗的令牌)               |
    |                                       |-- 验证 StateProof_v1 ---->|
    |                                       |<-- 已消耗！检测到重放 -|
    |                                       |                               |
    |                                       |-- 撤销所有会话 (aid) ->|
    |                                       |<-- 完成 ----------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (被盗) ------|
    |                                       |                               |
```

#### **4.5. 处理并发续订中的竞态条件**

在用户有多个标签页/窗口或续订请求几乎同时发生的情况下，存在 *误报* 重放检测的风险。JTS 定义了 **轮换宽限窗口** 机制来处理这种情况。

**问题：**
```
[标签页 A]                               [认证服务器]                    [数据库]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- 标记 SP_v1 已消耗 -------->|
    |                                     |                               |
[标签页 B]  (稍有延迟)              |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- 检查 SP_v1 --------------->|
    |                                     |<-- 已消耗！ (误报) |
    |<-- 401 JTS-401-05 ??? --------------|  (用户未被盗用!)      |
```

**解决方案：轮换宽限窗口**

服务器必须实现一个 **轮换宽限窗口**，并具有以下规范：

1.  **宽限窗口持续时间：** 服务器必须在轮换后将 `previous_state_proof` 存储 **5-10 秒**。
2.  **双重验证：** 在宽限窗口期间，服务器必须同时接受 `current_state_proof` 和 `previous_state_proof`。
3.  **对先前令牌的响应：** 如果请求使用仍在宽限窗口内的 `previous_state_proof`：
    -   服务器必须返回为 `current_state_proof` 生成的相同的 `StateProof` 和 `BearerPass`。
    -   服务器不得生成新令牌（防止令牌分歧）。
4.  **宽限窗口之后：** 使用已超过宽限窗口的 `previous_state_proof` 的请求必须被视为重放攻击。

**数据库实现：**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- 先前的令牌
    rotation_timestamp    TIMESTAMP,              -- 上次轮换发生的时间
    -- ... 其他列
);
```

**验证逻辑：**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 seconds
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // 返回现有令牌
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**并发续订图 (已处理)：**
```
[标签页 A]                               [认证服务器]                    [数据库]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- 轮换: SP_v1 -> SP_v2 ---->|
    |                                     |   (存储 previous=SP_v1)      |
    |<-- 200 OK (BP_new, SP_v2) ----------|                               |
    |                                     |                               |
[标签页 B]  (在 10 秒内)             |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- 检查 SP_v1 --------------->|
    |                                     |<-- 在 previous_sp 中找到,      |
    |                                     |    在宽限窗口内 -------|
    |<-- 200 OK (BP_new, SP_v2) ----------|  (与标签页 A 相同的令牌)       |
    |                                     |                               |
```

> **注意：** 两个标签页现在具有相同的 `StateProof` (SP_v2)，从而保持同步。

#### **4.6. 在途请求的宽限期**

为了处理 `BearerPass` 在请求传输过程中过期时的竞态条件：

**规范：**
-   资源服务器可以在 `exp` 时间之后提供一个时间容差 (*宽限期*)。
-   宽限期不得超过 **60 秒**。
-   如果有效负载中存在 `grc` 声明，其值定义了宽限期的秒数。
-   如果不存在 `grc` 声明，则默认宽限期为 **0 秒** (无容差)。

**验证逻辑：**
```
current_time = now()
effective_expiry = token.exp + token.grc (or 0 if grc is not present)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**注意：** 宽限期不会延长令牌用于审计目的的生命周期。原始的 `exp` 时间仍用于日志记录。

### **5. 轻量级配置文件：JTS-L (Lite)**

此配置文件专为需要易于实现且不牺牲 JTS 核心安全原则的低复杂度用例而设计。

#### **5.1. 何时使用 JTS-L**

JTS-L 适用于以下场景：

| 场景 | 建议 | 原因 |
| :--- | :--- | :--- |
| 创业公司 MVP / 原型 | ✅ JTS-L | 实现快速，以后可升级到 JTS-S。 |
| 内部工具 / 管理面板 | ✅ JTS-L | 用户群小，风险较低。 |
| 简单的单页应用 | ✅ JTS-L | 无需复杂的重放检测。 |
| 包含敏感数据的公共 API | ❌ 使用 JTS-S | 需要重放保护和设备绑定。 |
| 金融科技 / 医疗保健 | ❌ 使用 JTS-S/C | 需要最高的合规性和安全性。 |
| 多租户 SaaS | ❌ 使用 JTS-S | 需要隔离和完整的审计跟踪。 |

#### **5.2. 与 JTS-S 的主要区别**

| 特性 | JTS-S (标准) | JTS-L (轻量级) |
| :--- | :--- | :--- |
| StateProof 轮换 | ✅ 每次 `/renew` 强制 | ❌ 可选 |
| 重放检测 | ✅ 通过消耗标记内置 | ⚠️ 手动 / 无 |
| 设备指纹 (`dfp`) | ✅ 推荐 | ❌ 不需要 |
| 宽限期 (`grc`) | ✅ 支持 | ✅ 支持 |
| 扩展声明 | ✅ 完整 | ⚠️ 最小子集 |
| 并发会话策略 | ✅ 完整 | ⚠️ 仅 `allow_all` |
| 数据库复杂度 | 高 (跟踪已消耗的令牌) | 低 (简单的会话表) |
| 错误代码 | 完整 (所有代码) | 基本子集 |

#### **5.3. JTS-L `BearerPass` 结构**

JTS-L 中的 `BearerPass` 仍使用 **带非对称加密的 JWS**，但有效负载更精简。

**头部：**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**最小有效负载：**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**注意：** 在 JTS-L 中 `tkn_id` 声明是 **可选的**，因为不需要重放检测。

#### **5.4. JTS-L 工作流程 (简化)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS-L 简化流程                                         │
└─────────────────────────────────────────────────────────────────────────────┘

[客户端]                              [认证服务器]                    [数据库]
    │                                       │                               │
    │── POST /login (凭据) ─────────>│                               │
    │                                       │── 创建会话 ────────────>│
    │                                       │<── 会话 ID ────────────────│
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass (正文)                  │                               │
    │    StateProof (cookie)                │                               │
    │                                       │                               │
    │   ... BearerPass 过期 ...          │                               │
    │                                       │                               │
    │── POST /renew (StateProof) ──────────>│                               │
    │                                       │── 检查会话是否存在 ──────>│
    │                                       │<── 有效 ─────────────────────│
    │                                       │   (无轮换, 无消耗)  │
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass_new (正文)              │                               │
    │    (StateProof 未改变)             │                               │
    │                                       │                               │
```

**主要区别：**
-   每次 `/renew` 时 `StateProof` **不轮换** — 只要会话处于活动状态，就可以多次使用同一个令牌。
-   服务器只需检查数据库中是否存在会话记录，无需跟踪“已消耗”状态。
-   数据库复杂度显著降低。

#### **5.5. JTS-L 数据库模式**

JTS-L 的数据库要简单得多：

```sql
-- JTS-L: 简单的会话表
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- 锚点 ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- 主体 (用户 ID)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- 可选：用于会话列表
    ip_address      VARCHAR(45)               -- 可选：用于审计
);

-- 用于按用户查询的索引
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**与 JTS-S 的比较，后者需要：**
```sql
-- JTS-S: 带轮换跟踪的完整会话表
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- 用于宽限窗口
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- 重放检测
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... 更多列
);

-- 用于跟踪已消耗令牌的附加表
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. JTS-L 的错误代码子集**

JTS-L 仅需实现以下错误代码子集：

| 错误代码 | 错误键 | 描述 |
| :--- | :--- | :--- |
| `JTS-400-01` | `malformed_token` | 无法解析令牌。 |
| `JTS-401-01` | `bearer_expired` | BearerPass 已过期。 |
| `JTS-401-02` | `signature_invalid` | 签名无效。 |
| `JTS-401-03` | `stateproof_invalid` | StateProof 无效。 |
| `JTS-401-04` | `session_terminated` | 会话已终止。 |

**JTS-L 中不需要以下错误代码：**
-   `JTS-401-05` (session_compromised) — 无重放检测
-   `JTS-401-06` (device_mismatch) — 无设备绑定
-   `JTS-403-03` (org_mismatch) — 无多租户支持

#### **5.7. 从 JTS-L 迁移到 JTS-S**

JTS-L 被设计为随着安全需求的增加可以轻松升级到 JTS-S：

**迁移步骤：**

1.  **更新头部类型：**
    ```json
    // 之前
    { "typ": "JTS-L/v1" }
    // 之后
    { "typ": "JTS-S/v1" }
    ```

2.  **添加数据库列：**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **实现 StateProof 轮换：** 更新 `/renew` 逻辑以生成新的 StateProof。

4.  **向有效负载添加 `tkn_id`：** 开始为每个 BearerPass 生成唯一的令牌 ID。

5.  **逐步推出：**
    -   阶段 1: 服务器同时接受 JTS-L 和 JTS-S 令牌
    -   阶段 2: 所有新令牌均为 JTS-S
    -   阶段 3: 在最大会话生命周期后拒绝 JTS-L 令牌

#### **5.8. JTS-L 的局限性和风险**

> ⚠️ **警告：** 实施者在选择 JTS-L 之前必须了解以下风险：

| 风险 | 影响 | 缓解措施 |
| :--- | :--- | :--- |
| **无重放检测** | 被盗的 StateProof 可以被多次使用而不会被检测到。 | 为会话使用更短的 `exp`。 |
| **无设备绑定** | 令牌可以从不同的设备使用。 | 实施基于 IP 的速率限制。 |
| **盗窃未被检测** | 如果用户的令牌被盗，他们将不会收到通知。 | 监控登录模式，在新 IP 登录时通知。 |

**JTS-L 的缓解建议：**
-   设置更短的 `StateProof` 过期时间 (JTS-S 中最多 24 小时 vs. 7 天)
-   在 `/renew` 端点上实施速率限制
-   记录所有续订活动以进行手动审计
-   考虑为来自新 IP/位置的登录发送电子邮件通知

---

### **6. 机密性配置文件：JTS-C (Confidentiality)**

此配置文件为完全的有效负载机密性添加了一层加密。

#### **6.1. `BearerPass` 结构 (JWE 格式)**
JTS-C 配置文件中的 `BearerPass` 是一个 **JSON Web Encryption (JWE)**。来自标准配置文件的 JWS 令牌被“包装”或加密成 JWE。

#### **6.2. 工作流程**
*   **令牌创建 (“签名后加密”):**
    1.  如 JTS-S 配置文件中一样创建 JWS。
    2.  使用 **目标资源服务器的公钥** 加密整个 JWS。结果是一个 JWE。
*   **令牌验证 (“解密后验证”):**
    1.  资源服务器接收 JWE。
    2.  服务器使用 **自己的私钥** 解密 JWE。结果是原始的 JWS。
    3.  服务器使用 **认证服务器的公钥** 验证 JWS。

### **7. 安全分析和错误处理**

#### **7.1. 安全分析**

*   **会话撤销：** 通过服务器数据库中对 `StateProof` 的管理完全解决。
*   **凭据泄漏：** 通过强制使用非对称加密和在 `HttpOnly` cookie 中保护 `StateProof` 来最小化。
*   **信息泄漏：** 在 JTS-S/JTS-L 中通过精简的有效负载最小化，并在 JTS-C 中通过 JWE 加密完全解决。
*   **重放攻击：** 在 JTS-S 中通过唯一的 `tkn_id` 和 **StateProof 轮换** 来缓解。**注意：** JTS-L 不提供自动重放保护。
*   **XSS 攻击：** 由于 cookie 上的 `HttpOnly` 标志，`StateProof` 会话令牌被盗的风险显著降低。
*   **CSRF 攻击：** 通过 `SameSite=Strict` 和额外的头部验证相结合来缓解。
*   **令牌盗窃：** 在 JTS-S 中通过 **设备指纹 (`dfp`)** 来缓解。**注意：** JTS-L 不支持设备绑定。

#### **7.2. 标准错误代码**

JTS 定义了标准错误代码，以实现实施一致性和调试的便利性：

**错误响应格式：**
```json
{
  "error": "bearer_expired",
  "error_code": "JTS-401-01",
  "message": "BearerPass has expired",
  "action": "renew",
  "retry_after": 0,
  "timestamp": 1764515800
}
```

**错误代码列表：**

| 错误代码 | HTTP 状态 | 错误键 | 描述 | 操作 |
| :--- | :--- | :--- | :--- | :--- |
| `JTS-400-01` | 400 | `malformed_token` | 无法解析令牌或格式无效。 | `reauth` |
| `JTS-400-02` | 400 | `missing_claims` | 令牌中缺少必需的声明。 | `reauth` |
| `JTS-401-01` | 401 | `bearer_expired` | BearerPass 已过期。 | `renew` |
| `JTS-401-02` | 401 | `signature_invalid` | BearerPass 签名无效。 | `reauth` |
| `JTS-401-03` | 401 | `stateproof_invalid` | StateProof 无效或在数据库中未找到。 | `reauth` |
| `JTS-401-04` | 401 | `session_terminated` | 会话已终止（登出或并发策略）。 | `reauth` |
| `JTS-401-05` | 401 | `session_compromised` | 检测到重放攻击；所有会话均被撤销。 | `reauth` |
| `JTS-401-06` | 401 | `device_mismatch` | 设备指纹不匹配。 | `reauth` |
| `JTS-403-01` | 403 | `audience_mismatch` | 令牌不适用于此资源。 | `none` |
| `JTS-403-02` | 403 | `permission_denied` | 令牌不具有所需权限。 | `none` |
| `JTS-403-03` | 403 | `org_mismatch` | 令牌属于不同的组织/租户。 | `none` |
| `JTS-500-01` | 500 | `key_unavailable` | 用于验证的公钥不可用。 | `retry` |

**操作值：**
-   `renew`：客户端应调用 `/renew` 端点以获取新的 BearerPass。
-   `reauth`：用户必须重新进行身份验证（登录）。
-   `retry`：请求可以在 `retry_after` 秒后重试。
-   `none`：没有任何操作可以解决此问题。

### **8. 密钥管理**

#### **8.1. 密钥 ID 要求**

每个 `BearerPass` 的头部必须包含一个 `kid` (Key ID) 声明，以标识用于签名的密钥。

**带 kid 的头部格式：**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. 密钥轮换程序**

在不使已颁发的令牌失效的情况下更换签名密钥：

**步骤：**
1.  **生成新的密钥对：** 创建一个具有唯一 `kid` 的新密钥对。
2.  **发布公钥：** 将新的公钥添加到 JWKS 端点。服务器必须支持多个活动的公钥。
3.  **开始使用新密钥签名：** 所有新的 `BearerPass` 令牌都使用新密钥签名。
4.  **停用旧密钥：** 在 `max_bearer_lifetime` + 缓冲区（建议：15分钟）后，从 JWKS 中移除旧的公钥。

**JWKS 端点响应：**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-002",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "kid": "auth-server-key-2025-001",
      "use": "sig",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB",
      "exp": 1764520000
    }
  ]
}
```

**注意：** 密钥条目中的 `exp` 字段表示密钥将被停用的时间（可选，供客户端参考）。

#### **8.3. 标准 JWKS 端点**

JTS 为 JWKS (JSON Web Key Set) 端点定义了一个标准路径，以便资源服务器可以一致地找到公钥。

**标准路径：**
```
GET /.well-known/jts-jwks
```

**要求：**

| 方面 | 规范 |
| :--- | :--- |
| **路径** | `/.well-known/jts-jwks` (强制性) |
| **方法** | `GET` |
| **身份验证** | 不需要 (公共端点) |
| **Content-Type** | `application/json` |
| **CORS** | 必须允许来自有效域的跨域请求 |

**缓存：**

服务器必须包含适当的缓存头部：

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| 头部 | 推荐值 | 描述 |
| :--- | :--- | :--- |
| `Cache-Control` | `max-age=3600` | 缓存 1 小时。 |
| `stale-while-revalidate` | `60` | 在重新验证时允许使用 60 秒的陈旧响应。 |
| `ETag` | JWKS 内容的哈希 | 用于条件请求。 |

**发现 (可选)：**

为支持自动发现，认证服务器可以提供一个元数据端点：

```
GET /.well-known/jts-configuration
```

**响应：**
```json
{
  "issuer": "https://auth.example.com",
  "jwks_uri": "https://auth.example.com/.well-known/jts-jwks",
  "token_endpoint": "https://auth.example.com/jts/login",
  "renewal_endpoint": "https://auth.example.com/jts/renew",
  "revocation_endpoint": "https://auth.example.com/jts/logout",
  "supported_profiles": ["JTS-L/v1", "JTS-S/v1", "JTS-C/v1"],
  "supported_algorithms": ["RS256", "ES256"]
}
```

#### **8.4. 支持的算法**

JTS 推荐以下算法：

| 算法 | 类型 | 建议 | 注意 |
| :--- | :--- | :--- | :--- |
| `RS256` | 非对称 | 推荐 | 带 SHA-256 的 RSA，广泛支持。 |
| `RS384` | 非对称 | 支持 | 带 SHA-384 的 RSA。 |
| `RS512` | 非对称 | 支持 | 带 SHA-512 的 RSA。 |
| `ES256` | 非对称 | 推荐 | 带 P-256 的 ECDSA，效率更高。 |
| `ES384` | 非对称 | 支持 | 带 P-384 的 ECDSA。 |
| `ES512` | 非对称 | 支持 | 带 P-521 的 ECDSA。 |
| `PS256` | 非对称 | 支持 | 带 SHA-256 的 RSASSA-PSS。 |
| `HS256` | 对称 | **不允许** | 不符合 JTS 原则。 |
| `HS384` | 对称 | **不允许** | 不符合 JTS 原则。 |
| `HS512` | 对称 | **不允许** | 不符合 JTS 原则。 |
| `none` | - | **禁止** | 无签名，极不安全。 |

### **9. 并发会话策略**

JTS 定义了处理单个用户拥有多个活动会话情况的策略。

> **注意：** 并发会话策略仅适用于 **JTS-S** 和 **JTS-C**。**JTS-L** 配置文件默认仅支持 `allow_all` 策略。

#### **9.1. 策略选项**

| 策略 | `spl` 声明 | 行为 |
| :--- | :--- | :--- |
| **全部允许** | `allow_all` | 所有会话同时有效，无限制。 |
| **单一** | `single` | 只有一个活动会话。新登录会使旧的失效。 |
| **最多 N 个** | `max:3` | 最多 N 个活动会话。超过时最旧的会被驱逐。 |
| **通知** | `notify` | 所有会话都有效，但用户会收到其他会话的通知。 |

#### **9.2. 实现**

当用户登录且策略限制会话数量时：
```
1. 用户登录 -> 服务器检查此 `prn` 的活动会话数量
2. 如果数量 >= 限制：
   a. "single" 策略：撤销所有旧会话，创建一个新会话
   b. "max:n" 策略：撤销最旧的会话 (FIFO)，创建一个新会话
3. 在数据库中创建新的会话记录
4. 返回 StateProof 和 BearerPass
```

#### **9.3. 会话通知**

对于 `notify` 策略，服务器应提供一个端点来查看活动会话：

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

响应：
{
  "sessions": [
    {
      "aid": "session-anchor-abc",
      "device": "Chrome on Windows",
      "ip_prefix": "192.168.1.x",
      "created_at": 1764500000,
      "last_active": 1764515000,
      "current": true
    },
    {
      "aid": "session-anchor-def",
      "device": "Safari on iPhone",
      "ip_prefix": "10.0.0.x",
      "created_at": 1764400000,
      "last_active": 1764510000,
      "current": false
    }
  ]
}
```

### **10. 多平台支持**

#### **10.1. Web 平台 (默认)**

对于 Web 应用程序，`StateProof` 存储在 `HttpOnly` cookie 中，如第 4.3 节所述。

#### **10.2. 移动/原生平台**

对于 cookie 不实用的原生移动和桌面应用程序：

**存储：**
-   **iOS:** Keychain Services 与 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences 或 Keystore System
-   **桌面：** 操作系统凭据管理器 (Windows Credential Vault, macOS Keychain)

**StateProof 提交：**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**非 Cookie 的额外要求：**
-   `StateProof` 在客户端存储时必须加密。
-   带有 `X-JTS-StateProof` 头部的请求必须包含一个 `X-JTS-Device-ID` 以供验证。
-   服务器必须验证 `Device-ID` 与初始身份验证期间注册的 ID 匹配。

#### **10.3. 服务器到服务器 (M2M)**

对于机器到机器的通信：

-   不使用 `StateProof`（没有“用户会话”的概念）。
-   `BearerPass` 以更长的 `exp` 颁发（建议：1小时）。
-   `prn` 声明包含服务/机器标识符，而不是用户。
-   `atm` 声明设置为 `client_credentials`。

**M2M 示例有效负载：**
```json
{
  "prn": "service:payment-processor",
  "aid": "m2m-static-anchor",
  "tkn_id": "token-m2m-12345",
  "aud": "https://api.example.com/internal",
  "exp": 1764519000,
  "iat": 1764515400,
  "atm": "client_credentials",
  "perm": ["internal:process_payment", "internal:read_accounts"]
}
```

### **11. 结论**

Janus 令牌系统 (JTS) 提供了一个平衡的身份验证框架，将无状态验证的高性能与有状态会话管理的严格安全控制相结合。凭借其双组件架构、清晰的术语和灵活的操作配置文件，JTS 旨在成为下一代应用程序的强大而安全的身份验证标准。

**三种满足不同需求的配置文件：**

| 配置文件 | 用例 | 复杂度 | 安全性 |
| :--- | :--- | :--- | :--- |
| **JTS-L (轻量级)** | MVP, 内部工具, 简单应用 | ⭐ 低 | ⭐⭐ 基本 |
| **JTS-S (标准)** | 生产应用, 公共 API | ⭐⭐ 中 | ⭐⭐⭐⭐ 高 |
| **JTS-C (机密性)** | 金融科技, 医疗保健, 高安全 | ⭐⭐⭐ 高 | ⭐⭐⭐⭐⭐ 最高 |

**JTS 相对于上一代令牌系统的优势：**
1.  **即时撤销：** 通过 `StateProof` 管理和令牌轮换 (JTS-S/C)。
2.  **令牌盗窃检测：** 通过检测重放的轮换机制 (JTS-S/C)。
3.  **分层保护：** CSRF 保护、设备绑定和可选加密。
4.  **错误标准化：** 一致的错误代码，便于调试和处理。
5.  **平台灵活性：** 支持 Web、移动和服务器到服务器。
6.  **密钥管理：** 清晰的密钥轮换程序，无停机时间。
7.  **渐进增强：** 随着应用程序的增长，有清晰的从 JTS-L → JTS-S → JTS-C 的迁移路径。

---

### **附录 A: 实施清单**

实施者必须满足以下清单以符合 JTS 规范：

#### **JTS-L (轻量级) 清单：**

**必需 (必须):**
- [ ] 使用非对称加密 (RS256, ES256, 等)
- [ ] 在每个 BearerPass 的头部包含 `kid`
- [ ] 将 StateProof 存储在具有 SameSite=Strict 的 HttpOnly cookie 中
- [ ] 在 `/renew` 和 `/logout` 端点上验证 CSRF
- [ ] 根据标准格式返回错误响应 (子集)

**推荐 (应该):**
- [ ] 将 StateProof 过期时间设置为最多 24 小时
- [ ] 在 `/renew` 上实施速率限制
- [ ] 记录所有续订活动

---

#### **JTS-S (标准) 清单：**

**必需 (必须):**
- [ ] 使用非对称加密 (RS256, ES256, 等)
- [ ] 在每个 BearerPass 的头部包含 `kid`
- [ ] 将 StateProof 存储在具有 SameSite=Strict 的 HttpOnly cookie 中
- [ ] 在每次 `/renew` 时实施 StateProof 轮换
- [ ] 检测到重放时撤销会话
- [ ] 在 `/renew` 和 `/logout` 端点上验证 CSRF
- [ ] 根据标准格式返回错误响应 (完整)

**推荐 (应该):**
- [ ] 实施设备指纹 (`dfp`)
- [ ] 支持在途请求的宽限期
- [ ] 提供一个 `/sessions` 端点以提高可见性
- [ ] 实施并发会话策略
- [ ] 检测到异常时发送安全通知

**可选 (可以):**
- [ ] 实施一个内省端点
- [ ] 使用 `org` 声明支持多租户

---

#### **JTS-C (机密性) 清单：**

**必需 (必须):**
- [ ] 所有 JTS-S 要求
- [ ] 实施 JWE 加密 (签名后加密)
- [ ] 将加密密钥与签名密钥分开管理

**可选 (可以):**
- [ ] 支持多个资源服务器加密密钥
- [ ] 为加密密钥实施密钥交换协议

---

### **附录 B: 完整流程示例**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS 身份验证流程                                       │
└─────────────────────────────────────────────────────────────────────────────┘

[用户]          [客户端应用]         [认证服务器]        [资源服务器]
   │                 │                     │                      │
   │─── 登录 ──────>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (凭据)    │                      │
   │                 │                     │── 创建会话 ───>│ [DB]
   │                 │                     │<─ 会话记录 ────│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (正文)│                      │
   │                 │    StateProof (cookie)                     │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    验证签名  │
   │                 │                     │    (无状态)       │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── 数据 ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass 过期 ...        │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (StateProof cookie)                     │
   │                 │                     │── 验证 SP_v1 ───>│ [DB]
   │                 │                     │<─ 有效, 已消耗 ───│
   │                 │                     │── 存储 SP_v2 ──────>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass_new   │                      │
   │                 │    StateProof_v2 (cookie)                  │
   │                 │                     │                      │
   │─── 登出 ─────>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (StateProof cookie)                     │
   │                 │                     │── 删除会话 ───>│ [DB]
   │                 │<── 200 OK ─────────│                      │
   │<── 已登出 ─│                     │                      │
   │                 │                     │                      │
```

---

### **附录 C: 参考文献**

-   RFC 7519 - JSON Web Token (JWT)
-   RFC 7515 - JSON Web Signature (JWS)
-   RFC 7516 - JSON Web Encryption (JWE)
-   RFC 7517 - JSON Web Key (JWK)
-   RFC 6749 - The OAuth 2.0 Authorization Framework
-   OWASP Session Management Cheat Sheet
-   OWASP Cross-Site Request Forgery Prevention Cheat Sheet
