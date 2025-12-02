
# 프로젝트 아카이브 문서: 야누스 토큰 시스템(JTS)

**제목:** 야누스 토큰 시스템(JTS): 안전하고, 철회 가능하며, 기밀성 있는 API 인증을 위한 2요소 아키텍처

**상태:** 표준 초안, 버전 1.1

**저자/개척자:** ukungzulfah

**발행일:** 2025년 11월 30일

> **초록:**
> 이 문서는 현대 분산 애플리케이션 생태계(예: 마이크로서비스 아키텍처)의 보안 및 확장성 문제를 해결하기 위해 설계된 새로운 인증 표준인 **야누스 토큰 시스템(JTS)**을 정의합니다. JTS는 **단기 액세스 증명(`BearerPass`)**과 **장기 세션 증명(`StateProof`)**을 근본적으로 분리하는 2요소 아키텍처를 도입합니다. 이 접근 방식은 즉각적인 세션 철회를 포함하여 *상태 저장(stateful)* 세션 관리의 중요한 기능을 유지하면서 매우 빠르고 *상태 비저장(stateless)* 액세스 검증을 가능하게 합니다. 이 문서는 세 가지 운영 프로필을 정의합니다: 완전한 보안 기능을 갖춘 완전한 무결성을 위한 **JTS-S(표준)**, 최소한의 복잡성으로 경량 구현을 위한 **JTS-L(라이트)**, 그리고 완전한 페이로드 기밀성을 위한 **JTS-C(기밀성)**입니다. 이 사양은 또한 덜 직관적인 레거시 용어를 대체하기 위한 새로운 클레임 용어를 도입합니다.

---

### **저작권 라이선스**
> Copyright © 2025, ukungzulfah. All Rights Reserved.
>
> 본 사양 및 관련 문서("소프트웨어")의 사본을 취득하는 모든 사람에게 다음 조건에 따라 소프트웨어의 사본을 사용, 복사, 수정, 병합, 게시, 배포 및/또는 판매할 수 있는 권한을 무료로 부여합니다:
>
> 위의 저작권 고지 및 이 허가 고지는 소프트웨어의 모든 사본 또는 상당 부분에 포함되어야 합니다. 소프트웨어는 어떠한 종류의 명시적 또는 묵시적 보증 없이 "있는 그대로" 제공됩니다.

---

### **1. 서론**

#### **1.1. 현대 인증의 과제**
현대 소프트웨어 아키텍처에서 애플리케이션은 작고 독립적인 서비스(마이크로서비스)로 분해됩니다. 이 모델은 경량이고 분산되어 있으며 단일의 모놀리식 중앙 집중식 세션에 의존하지 않는 인증 시스템을 요구합니다.

#### **1.2. 초기 세대 상태 비저장 토큰 모델의 한계**
1세대 상태 비저장 토큰 기반 인증 모델은 부분적인 해결책을 제공했지만 상당한 약점을 도입했습니다:
1.  **세션 철회 취약점:** 발행된 토큰은 만료 시간 전에 서버 측에서 강제로 무효화할 수 없습니다.
2.  **정보 노출:** 토큰 페이로드는 종종 암호화되지 않고 인코딩만 되어 있으므로 토큰을 보유한 모든 당사자가 내부 데이터를 읽을 수 있습니다.
3.  **키 관리 복잡성:** 분산 환경에서 공유 대칭 키를 사용하면 고위험 단일 실패 지점이 생성됩니다.

#### **1.3. 새로운 패러다임: 야누스 토큰 시스템(JTS)**
JTS는 이러한 약점을 해결하기 위한 진화로 제안됩니다. 이중성 원칙을 통해 JTS는 *상태 비저장* 효율성과 *상태 저장* 보안을 결합합니다.

### **2. JTS 핵심 개념**

#### **2.1. 이중성 원칙**
JTS는 토큰의 역할을 두 가지로 분리합니다:
1.  **액세스:** 매우 짧은 기간 동안 리소스에 대한 액세스 권한을 부여합니다.
2.  **세션:** 사용자의 전체 인증 세션의 유효성을 증명합니다.

#### **2.2. JTS의 두 가지 구성 요소**
1.  **`BearerPass`:** 암호화 서명된 단기 액세스 토큰. 모든 API 요청에 사용되며 상태 비저장 방식으로 검증됩니다.
2.  **`StateProof`:** 불투명하고 상태 저장인 장기 세션 토큰. 새로운 `BearerPass`를 얻기 위해 독점적으로 사용되며 클라이언트 측에 안전하게 저장됩니다. 서버 데이터베이스에서의 존재 여부가 세션의 유효성을 결정합니다.

### **3. JTS 용어 및 클레임**

개선 사항으로, JTS는 모호한 레거시 용어에서 벗어나 더 명시적이고 직관적인 클레임 용어를 도입합니다.

| JTS 클레임 | 전체 이름 | 설명 | 대체 |
| :--- | :--- | :--- | :--- |
| **`prn`** | **Principal** | 인증된 주체(일반적으로 사용자)의 고유 식별자. | `sub` |
| **`aid`** | **Anchor ID** | `BearerPass`를 서버의 세션 레코드에 "고정"하는 고유 ID. | `sid` |
| **`tkn_id`**| **Token ID** | 각 `BearerPass`의 고유 식별자로, 재생 공격을 방지합니다. | `jti` |
| `exp` | Expiration Time | 토큰 만료 시간 (RFC 7519에서 유지). | - |
| `aud` | Audience | 이 토큰의 의도된 수신자 (RFC 7519에서 유지). | - |
| `iat` | Issued At | 토큰이 발급된 시간 (RFC 7519에서 유지). | - |

#### **3.2. 확장 클레임**

JTS는 더 강력한 보안 및 기능을 위해 추가 클레임을 정의합니다:

| JTS 클레임 | 전체 이름 | 설명 | 필수 |
| :--- | :--- | :--- | :--- |
| **`dfp`** | **Device Fingerprint** | 토큰을 특정 장치에 바인딩하기 위한 장치 특성의 해시. | 아니오 |
| **`perm`**| **Permissions** | 토큰이 보유한 권한/범위를 정의하는 문자열 배열. | 아니오 |
| **`grc`** | **Grace Period** | 진행 중인 요청에 대해 `exp` 이후의 시간 허용 오차(초). | 아니오 |
| **`org`** | **Organization** | 다중 테넌트 시스템을 위한 테넌트/조직 식별자. | 아니오 |
| **`atm`** | **Auth Method** | 사용된 인증 방법 (예: `pwd`, `mfa:totp`, `sso`). | 아니오 |
| **`ath`** | **Auth Time** | 사용자가 마지막으로 활성 인증을 수행한 Unix 타임스탬프. | 아니오 |
| **`spl`** | **Session Policy** | 적용 중인 동시 세션 정책 (`allow_all`, `single`, `max:n`). | 아니오 |

**확장 클레임이 포함된 페이로드 예시:**
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

### **4. 표준 프로필: JTS-S (무결성)**

이 프로필은 속도, 무결성 및 세션 철회 기능에 중점을 둡니다.

#### **4.1. `BearerPass` 구조 (JWS 형식)**
JTS-S 프로필의 `BearerPass`는 **비대칭 암호화(예: RS256)**로 서명된 **JSON 웹 서명(JWS)**입니다.

**헤더 예시:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**참고:** `kid`(키 ID) 클레임은 키 순환을 지원하기 위해 필수입니다 (섹션 7 참조).

**페이로드 예시:**
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

#### **4.2. 워크플로**
1.  **인증:** 사용자가 로그인 -> 서버가 DB에 세션 레코드를 생성하고, `StateProof`(DB에 저장)와 `BearerPass`(JWS)를 생성합니다. `StateProof`는 `HttpOnly` 쿠키를 통해 전송되고 `BearerPass`는 JSON 본문을 통해 전송됩니다.
2.  **리소스 액세스:** 클라이언트가 헤더에 `BearerPass`를 전송 -> 서버가 공개 키를 사용하여 JWS 서명을 확인합니다.
3.  **갱신:** `BearerPass` 만료 -> 클라이언트가 쿠키의 `StateProof`를 사용하여 `/renew` 엔드포인트를 호출 -> 서버가 DB에서 `StateProof`를 확인하고, 유효하면 새 `BearerPass`를 발급합니다.
4.  **철회(로그아웃):** 클라이언트가 `/logout`을 호출 -> 서버가 `StateProof`와 관련된 세션 레코드를 DB에서 삭제합니다. 세션은 즉시 무효화됩니다.

#### **4.3. 쿠키 요구 사항 및 CSRF 보호**

쿠키에 저장된 `StateProof`는 다음 보안 요구 사항을 충족해야 합니다:

**필수 쿠키 속성:**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| 속성 | 값 | 설명 |
| :--- | :--- | :--- |
| `HttpOnly` | 필수 | 자바스크립트에서의 접근을 방지합니다 (XSS 완화). |
| `Secure` | 필수 | 쿠키는 HTTPS를 통해서만 전송됩니다. |
| `SameSite` | `Strict` | 교차 사이트 요청 시 쿠키 전송을 방지합니다 (CSRF 완화). |
| `Path` | `/jts` | 쿠키가 JTS 엔드포인트로만 전송되도록 제한합니다. |
| `Max-Age` | 정책에 따라 | 세션 정책에 따른 쿠키 수명. |

**추가 CSRF 보호:**

`/renew` 및 `/logout` 엔드포인트의 경우, 서버는 다음 메커니즘 중 하나 이상을 검증해야 합니다:

1.  **Origin 헤더 검증:** `Origin` 또는 `Referer` 헤더가 허용된 도메인에서 오는지 확인합니다.
2.  **사용자 지정 헤더 요구 사항:** 표준 양식 제출로 설정할 수 없는 사용자 지정 헤더를 요구합니다:
    ```
    X-JTS-Request: 1
    ```
3.  **이중 제출 쿠키 패턴:** CSRF 토큰 값을 쿠키와 요청 본문/헤더 모두에 보내고 일치하는지 확인합니다.

#### **4.4. StateProof 순환**

보안을 강화하고 토큰 도용을 감지하기 위해, JTS는 모든 갱신 작업에서 `StateProof` 순환을 요구합니다.

**메커니즘:**
1.  클라이언트가 이전 `StateProof`로 `/renew`를 호출합니다.
2.  서버가 데이터베이스에서 이전 `StateProof`를 확인합니다.
3.  유효한 경우:
    a.  서버는 이전 `StateProof`를 삭제하거나 *소비됨*으로 표시합니다.
    b.  서버는 새 `StateProof`와 새 `BearerPass`를 발급합니다.
    c.  새 `StateProof`는 `Set-Cookie` 헤더를 통해 전송됩니다.
4.  이전 `StateProof`가 이미 *소비됨*으로 표시된 경우 (재생 감지):
    a.  서버는 해당 `aid`와 관련된 모든 세션을 즉시 철회해야 합니다.
    b.  서버는 `JTS-401-05`(세션 손상됨) 오류를 반환해야 합니다.
    c.  서버는 사용자에게 보안 알림을 보내야 합니다.

**순환 다이어그램:**
```
[클라이언트]                           [인증 서버]                     [데이터베이스]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- StateProof_v1 확인 ---->|
    |                                       |<-- 유효, 소비됨으로 표시 ---|
    |                                       |                               |
    |                                       |-- StateProof_v2 생성 ---->|
    |                                       |<-- 저장됨 --------------------|
    |                                       |                               |
    |<-- 200 OK (새 BearerPass) ------------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**이상 감지 (재생 공격):**
```
[공격자]                              [인증 서버]                     [데이터베이스]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (도난된 토큰)                |
    |                                       |-- StateProof_v1 확인 ---->|
    |                                       |<-- 소비됨! 재생 감지됨 -|
    |                                       |                               |
    |                                       |-- 모든 세션 철회 (aid) ->|
    |                                       |<-- 완료 ----------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (손상됨) -----------|
    |                                       |                               |
```

#### **4.5. 동시 갱신에서의 경쟁 조건 처리**

사용자가 여러 탭/창을 가지고 있거나 갱신 요청이 거의 동시에 발생하는 시나리오에서는 *거짓 양성* 재생 감지 위험이 있습니다. JTS는 이 조건을 처리하기 위해 **순환 유예 창** 메커니즘을 정의합니다.

**문제:**
```
[탭 A]                                 [인증 서버]                     [데이터베이스]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- SP_v1을 소비됨으로 표시 -->|
    |                                     |                               |
[탭 B]  (약간 지연됨)                   |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- SP_v1 확인 --------------->|
    |                                     |<-- 소비됨! (거짓 양성) |
    |<-- 401 JTS-401-05 ??? --------------|  (사용자가 손상되지 않음!)    |
```

**해결책: 순환 유예 창**

서버는 다음 사양으로 **순환 유예 창**을 구현해야 합니다:

1.  **유예 창 기간:** 서버는 순환 후 **5-10초** 동안 `previous_state_proof`를 저장해야 합니다.
2.  **이중 검증:** 유예 창 동안 서버는 `current_state_proof`와 `previous_state_proof`를 모두 수락해야 합니다.
3.  **이전 토큰에 대한 응답:** 요청이 아직 유예 창 내에 있는 `previous_state_proof`를 사용하는 경우:
    -   서버는 `current_state_proof`에 대해 이미 생성된 동일한 `StateProof`와 `BearerPass`를 반환해야 합니다.
    -   서버는 새 토큰을 생성해서는 안 됩니다 (토큰 분기 방지).
4.  **유예 창 이후:** 유예 창을 지난 `previous_state_proof`를 가진 요청은 재생 공격으로 처리되어야 합니다.

**데이터베이스 구현:**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- 이전 토큰
    rotation_timestamp    TIMESTAMP,              -- 마지막 순환 발생 시점
    -- ... 다른 열
);
```

**검증 로직:**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 seconds
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // 기존 토큰 반환
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**동시 갱신 다이어그램 (처리됨):**
```
[탭 A]                                 [인증 서버]                     [데이터베이스]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- 순환: SP_v1 -> SP_v2 ---->|
    |                                     |   (previous=SP_v1 저장)     |
    |<-- 200 OK (새 BP, SP_v2) ------------|                               |
    |                                     |                               |
[탭 B]  (10초 이내)                      |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- SP_v1 확인 --------------->|
    |                                     |<-- previous_sp에서 찾음,    |
    |                                     |    유예 창 내에 있음 -------|
    |<-- 200 OK (새 BP, SP_v2) ------------|  (탭 A와 동일한 토큰)      |
    |                                     |                               |
```

> **참고:** 이제 두 탭 모두 동일한 `StateProof`(SP_v2)를 가지므로 동기화된 상태를 유지합니다.

#### **4.6. 진행 중인 요청에 대한 유예 기간**

`BearerPass`가 요청 진행 중에 만료되는 경쟁 조건을 처리하기 위해:

**사양:**
-   리소스 서버는 `exp` 시간 이후에 시간 허용 오차(*유예 기간*)를 제공할 수 있습니다.
-   유예 기간은 **60초**를 초과해서는 안 됩니다.
-   페이로드에 `grc` 클레임이 있는 경우, 해당 값이 유예 기간을 초 단위로 정의합니다.
-   `grc` 클레임이 없는 경우, 기본 유예 기간은 **0초**입니다(허용 오차 없음).

**검증 로직:**
```
current_time = now()
effective_expiry = token.exp + token.grc (or 0 if grc is not present)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**참고:** 유예 기간은 감사 목적으로 토큰의 수명을 연장하지 않습니다. 원래 `exp` 시간은 여전히 로깅에 사용됩니다.

### **5. 라이트 프로필: JTS-L (Lite)**

이 프로필은 JTS의 핵심 보안 원칙을 희생하지 않으면서 구현의 용이성을 요구하는 저 복잡도 사용 사례를 위해 설계되었습니다.

#### **5.1. JTS-L 사용 시기**

JTS-L은 다음 시나리오에 적합합니다:

| 시나리오 | 권장 | 이유 |
| :--- | :--- | :--- |
| 스타트업 MVP / 프로토타입 | ✅ JTS-L | 구현이 빠르고 나중에 JTS-S로 업그레이드 가능. |
| 내부 도구 / 관리자 패널 | ✅ JTS-L | 사용자 기반이 작고 위험이 낮음. |
| 간단한 단일 페이지 애플리케이션 | ✅ JTS-L | 복잡한 재생 감지가 필요 없음. |
| 민감한 데이터가 있는 공개 API | ❌ JTS-S 사용 | 재생 보호 및 장치 바인딩 필요. |
| 핀테크 / 헬스케어 | ❌ JTS-S/C 사용 | 최대 규정 준수 및 보안 필요. |
| 다중 테넌트 SaaS | ❌ JTS-S 사용 | 격리 및 완전한 감사 추적 필요. |

#### **5.2. JTS-S와의 주요 차이점**

| 기능 | JTS-S (표준) | JTS-L (라이트) |
| :--- | :--- | :--- |
| StateProof 순환 | ✅ `/renew`마다 필수 | ❌ 선택 사항 |
| 재생 감지 | ✅ 소비됨 표시를 통한 내장 | ⚠️ 수동 / 없음 |
| 장치 지문 (`dfp`) | ✅ 권장 | ❌ 불필요 |
| 유예 기간 (`grc`) | ✅ 지원 | ✅ 지원 |
| 확장 클레임 | ✅ 전체 | ⚠️ 최소 하위 집합 |
| 동시 세션 정책 | ✅ 전체 | ⚠️ `allow_all`만 |
| 데이터베이스 복잡성 | 높음 (소비된 토큰 추적) | 낮음 (간단한 세션 테이블) |
| 오류 코드 | 전체 (모든 코드) | 필수 하위 집합 |

#### **5.3. JTS-L `BearerPass` 구조**

JTS-L의 `BearerPass`는 여전히 **비대칭 암호화를 사용하는 JWS**를 사용하지만, 더 미니멀리스트적인 페이로드입니다.

**헤더:**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**최소 페이로드:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**참고:** JTS-L에서는 재생 감지가 필요 없으므로 `tkn_id` 클레임은 **선택 사항**입니다.

#### **5.4. JTS-L 워크플로 (단순화)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS-L 단순화된 흐름                                 │
└─────────────────────────────────────────────────────────────────────────────┘

[클라이언트]                           [인증 서버]                     [데이터베이스]
    │                                       |                               |
    │── POST /login (자격 증명) ──────────>│                               |
    │                                       │── 세션 생성 ─────────────>│
    │                                       │<── 세션 ID ─────────────────│
    │<── 200 OK ────────────────────────────│                               |
    │    BearerPass (본문)                  │                               |
    │    StateProof (쿠키)                  │                               |
    │                                       │                               |
    │   ... BearerPass 만료 ...            │                               |
    │                                       │                               |
    │── POST /renew (StateProof) ──────────>│                               |
    │                                       │── 세션 존재 확인 ───────>│
    │                                       │<── 유효 ───────────────────│
    │                                       │   (순환 없음, 소비됨 없음)    │
    │<── 200 OK ────────────────────────────│                               |
    │    새 BearerPass (본문)               │                               |
    │    (StateProof 변경 없음)             │                               |
    │                                       │                               |
```

**주요 차이점:**
-   `StateProof`는 각 `/renew`마다 **순환되지 않습니다**—세션이 활성 상태인 동안 동일한 토큰을 여러 번 사용할 수 있습니다.
-   서버는 "소비됨" 상태를 추적할 필요 없이 데이터베이스에 세션 레코드가 **존재**하는지만 확인하면 됩니다.
-   데이터베이스 복잡성이 크게 줄어듭니다.

#### **5.5. JTS-L 데이터베이스 스키마**

JTS-L의 데이터베이스는 훨씬 간단합니다:

```sql
-- JTS-L: 간단한 세션 테이블
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- 앵커 ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- 주체 (사용자 ID)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- 선택 사항: 세션 목록용
    ip_address      VARCHAR(45)               -- 선택 사항: 감사용
);

-- 사용자별 쿼리용 인덱스
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**JTS-S가 요구하는 것과 비교:**
```sql
-- JTS-S: 순환 추적이 있는 전체 세션 테이블
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- 유예 창용
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- 재생 감지
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... 더 많은 열
);

-- 소비된 토큰 추적용 추가 테이블
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. JTS-L용 오류 코드 하위 집합**

JTS-L은 다음 오류 코드 하위 집합만 구현해야 합니다:

| 오류 코드 | 오류 키 | 설명 |
| :--- | :--- | :--- |
| `JTS-400-01` | `malformed_token` | 토큰을 구문 분석할 수 없습니다. |
| `JTS-401-01` | `bearer_expired` | BearerPass가 만료되었습니다. |
| `JTS-401-02` | `signature_invalid` | 서명이 잘못되었습니다. |
| `JTS-401-03` | `stateproof_invalid` | StateProof가 잘못되었습니다. |
| `JTS-401-04` | `session_terminated` | 세션이 종료되었습니다. |

**JTS-L에서 필요하지 않은 오류 코드:**
-   `JTS-401-05` (session_compromised) — 재생 감지 없음
-   `JTS-401-06` (device_mismatch) — 장치 바인딩 없음
-   `JTS-403-03` (org_mismatch) — 다중 테넌트 지원 없음

#### **5.7. JTS-L에서 JTS-S로 마이그레이션**

JTS-L은 보안 요구 사항이 증가함에 따라 JTS-S로 쉽게 업그레이드할 수 있도록 설계되었습니다:

**마이그레이션 단계:**

1.  **헤더 유형 업데이트:**
    ```json
    // 이전
    { "typ": "JTS-L/v1" }
    // 이후
    { "typ": "JTS-S/v1" }
    ```

2.  **데이터베이스 열 추가:**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **StateProof 순환 구현:** `/renew` 로직을 업데이트하여 새 StateProof를 생성합니다.

4.  **페이로드에 `tkn_id` 추가:** 각 BearerPass에 대해 고유한 토큰 ID를 생성하기 시작합니다.

5.  **점진적 출시:**
    -   1단계: 서버가 JTS-L 및 JTS-S 토큰을 모두 수락
    -   2단계: 모든 새 토큰은 JTS-S
    -   3단계: 최대 세션 수명 후 JTS-L 토큰 거부

#### **5.8. JTS-L의 한계 및 위험**

> ⚠️ **경고:** 구현자는 JTS-L을 선택하기 전에 다음 위험을 이해해야 합니다:

| 위험 | 영향 | 완화 |
| :--- | :--- | :--- |
| **재생 감지 없음** | 도난당한 StateProof는 감지 없이 여러 번 사용될 수 있습니다. | 세션에 더 짧은 `exp`를 사용하십시오. |
| **장치 바인딩 없음** | 토큰은 다른 장치에서 사용될 수 있습니다. | IP 기반 속도 제한을 구현하십시오. |
| **도난이 감지되지 않음**| 사용자의 토큰이 도난당해도 알림을 받지 못합니다. | 로그인 패턴을 모니터링하고 새 IP에서 알림을 보냅니다. |

**JTS-L에 대한 완화 권장 사항:**
-   `StateProof` 만료를 더 짧게 설정 (JTS-S의 7일에 비해 최대 24시간)
-   `/renew` 엔드포인트에 속도 제한 구현
-   수동 감사를 위해 모든 갱신 활동 기록
-   새 IP/위치에서의 로그인에 대한 이메일 알림 고려

---

### **6. 기밀성 프로필: JTS-C (Confidentiality)**

이 프로필은 완전한 페이로드 기밀성을 위해 암호화 계층을 추가합니다.

#### **6.1. `BearerPass` 구조 (JWE 형식)**
JTS-C 프로필의 `BearerPass`는 **JSON 웹 암호화(JWE)**입니다. 표준 프로필의 JWS 토큰은 JWE로 "래핑"되거나 암호화됩니다.

#### **6.2. 워크플로**
*   **토큰 생성("서명 후 암호화"):**
    1.  JTS-S 프로필과 같이 JWS를 생성합니다.
    2.  의도된 리소스 서버의 **공개 키**를 사용하여 전체 JWS를 암호화합니다. 결과는 JWE입니다.
*   **토큰 검증("복호화 후 검증"):**
    1.  리소스 서버가 JWE를 수신합니다.
    2.  서버는 **자신의 개인 키**를 사용하여 JWE를 복호화합니다. 결과는 원래 JWS입니다.
    3.  서버는 **인증 서버의 공개 키**를 사용하여 JWS를 확인합니다.

### **7. 보안 분석 및 오류 처리**

#### **7.1. 보안 분석**

*   **세션 철회:** 서버 데이터베이스에서 `StateProof` 관리를 통해 완전히 해결됩니다.
*   **자격 증명 유출:** 비대칭 암호화의 필수 사용 및 `HttpOnly` 쿠키에서 `StateProof`를 보호함으로써 최소화됩니다.
*   **정보 유출:** JTS-S/JTS-L에서는 미니멀리스트 페이로드로 최소화되고, JTS-C에서는 JWE 암호화를 통해 완전히 해결됩니다.
*   **재생 공격:** JTS-S에서는 고유한 `tkn_id`와 **StateProof 순환**으로 완화됩니다. **참고:** JTS-L은 자동 재생 보호를 제공하지 않습니다.
*   **XSS 공격:** 쿠키의 `HttpOnly` 플래그로 인해 `StateProof` 세션 토큰 도난 위험이 크게 줄어듭니다.
*   **CSRF 공격:** `SameSite=Strict`와 추가 헤더 검증의 조합으로 완화됩니다.
*   **토큰 도난:** JTS-S에서는 **장치 지문(`dfp`)**으로 완화됩니다. **참고:** JTS-L은 장치 바인딩을 지원하지 않습니다.

#### **7.2. 표준 오류 코드**

JTS는 구현 일관성 및 디버깅 용이성을 위해 표준 오류 코드를 정의합니다:

**오류 응답 형식:**
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

**오류 코드 목록:**

| 오류 코드 | HTTP 상태 | 오류 키 | 설명 | 조치 |
| :--- | :--- | :--- | :--- | :--- |
| `JTS-400-01` | 400 | `malformed_token` | 토큰을 구문 분석할 수 없거나 형식이 잘못되었습니다. | `reauth` |
| `JTS-400-02` | 400 | `missing_claims` | 토큰에 필요한 클레임이 없습니다. | `reauth` |
| `JTS-401-01` | 401 | `bearer_expired` | BearerPass가 만료되었습니다. | `renew` |
| `JTS-401-02` | 401 | `signature_invalid` | BearerPass 서명이 잘못되었습니다. | `reauth` |
| `JTS-401-03` | 401 | `stateproof_invalid` | StateProof가 잘못되었거나 DB에서 찾을 수 없습니다. | `reauth` |
| `JTS-401-04` | 401 | `session_terminated` | 세션이 종료되었습니다(로그아웃 또는 동시 정책). | `reauth` |
| `JTS-401-05` | 401 | `session_compromised`| 재생 공격이 감지되었습니다. 모든 세션이 철회됩니다. | `reauth` |
| `JTS-401-06` | 401 | `device_mismatch` | 장치 지문이 일치하지 않습니다. | `reauth` |
| `JTS-403-01` | 403 | `audience_mismatch` | 토큰이 이 리소스용이 아닙니다. | `none` |
| `JTS-403-02` | 403 | `permission_denied` | 토큰에 필요한 권한이 없습니다. | `none` |
| `JTS-403-03` | 403 | `org_mismatch` | 토큰이 다른 조직/테넌트에 속합니다. | `none` |
| `JTS-500-01` | 500 | `key_unavailable` | 확인용 공개 키를 사용할 수 없습니다. | `retry` |

**조치 값:**
-   `renew`: 클라이언트는 새 BearerPass를 얻기 위해 `/renew` 엔드포인트를 호출해야 합니다.
-   `reauth`: 사용자는 다시 인증해야 합니다(로그인).
-   `retry`: 요청은 `retry_after` 초 후에 다시 시도할 수 있습니다.
-   `none`: 어떤 조치도 이 상태를 해결할 수 없습니다.

### **8. 키 관리**

#### **8.1. 키 ID 요구 사항**

모든 `BearerPass`는 서명에 사용된 키를 식별하기 위해 헤더에 `kid`(키 ID) 클레임을 포함해야 합니다.

**kid가 있는 헤더 형식:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. 키 순환 절차**

이미 발급된 토큰을 무효화하지 않고 서명 키를 교체하려면:

**단계:**
1.  **새 키 쌍 생성:** 고유한 `kid`를 가진 새 키 쌍을 만듭니다.
2.  **공개 키 게시:** 새 공개 키를 JWKS 엔드포인트에 추가합니다. 서버는 여러 활성 공개 키를 지원해야 합니다.
3.  **새 키로 서명 시작:** 모든 새 `BearerPass` 토큰은 새 키로 서명됩니다.
4.  **이전 키 폐기:** `max_bearer_lifetime` + 버퍼(권장: 15분) 후, 이전 공개 키를 JWKS에서 제거합니다.

**JWKS 엔드포인트 응답:**
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

**참고:** 키 항목의 `exp` 필드는 키가 폐기될 시기를 나타냅니다(선택 사항, 클라이언트 정보용).

#### **8.3. 표준 JWKS 엔드포인트**

JTS는 리소스 서버가 공개 키를 일관되게 찾을 수 있도록 JWKS(JSON 웹 키 세트) 엔드포인트의 표준 경로를 정의합니다.

**표준 경로:**
```
GET /.well-known/jts-jwks
```

**요구 사항:**

| 측면 | 사양 |
| :--- | :--- |
| **경로** | `/.well-known/jts-jwks` (필수) |
| **메서드** | `GET` |
| **인증** | 필요 없음 (공개 엔드포인트) |
| **Content-Type** | `application/json` |
| **CORS** | 유효한 도메인에서의 교차 출처 요청을 허용해야 합니다 |

**캐싱:**

서버는 적절한 캐싱 헤더를 포함해야 합니다:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| 헤더 | 권장 값 | 설명 |
| :--- | :--- | :--- |
| `Cache-Control` | `max-age=3600` | 1시간 동안 캐시합니다. |
| `stale-while-revalidate`| `60` | 재검증하는 동안 60초 동안 오래된 응답을 허용합니다. |
| `ETag` | JWKS 콘텐츠의 해시 | 조건부 요청용. |

**검색(선택 사항):**

자동 검색을 지원하기 위해 인증 서버는 메타데이터 엔드포인트를 제공할 수 있습니다:

```
GET /.well-known/jts-configuration
```

**응답:**
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

#### **8.4. 지원되는 알고리즘**

JTS는 다음 알고리즘을 권장합니다:

| 알고리즘 | 유형 | 권장 | 참고 |
| :--- | :--- | :--- | :--- |
| `RS256` | 비대칭 | 권장 | SHA-256을 사용하는 RSA, 널리 지원됨. |
| `RS384` | 비대칭 | 지원 | SHA-384를 사용하는 RSA. |
| `RS512` | 비대칭 | 지원 | SHA-512를 사용하는 RSA. |
| `ES256` | 비대칭 | 권장 | P-256을 사용하는 ECDSA, 더 효율적. |
| `ES384` | 비대칭 | 지원 | P-384를 사용하는 ECDSA. |
| `ES512` | 비대칭 | 지원 | P-521을 사용하는 ECDSA. |
| `PS256` | 비대칭 | 지원 | SHA-256을 사용하는 RSASSA-PSS. |
| `HS256` | 대칭 | **허용 안 함** | JTS 원칙과 맞지 않음. |
| `HS384` | 대칭 | **허용 안 함** | JTS 원칙과 맞지 않음. |
| `HS512` | 대칭 | **허용 안 함** | JTS 원칙과 맞지 않음. |
| `none` | - | **금지** | 서명 없음, 매우 안전하지 않음. |

### **9. 동시 세션 정책**

JTS는 단일 사용자가 여러 활성 세션을 가질 때의 상황을 처리하기 위한 정책을 정의합니다.

> **참고:** 동시 세션 정책은 **JTS-S** 및 **JTS-C**에만 적용됩니다. **JTS-L** 프로필은 기본적으로 `allow_all` 정책만 지원합니다.

#### **9.1. 정책 옵션**

| 정책 | `spl` 클레임 | 동작 |
| :--- | :--- | :--- |
| **모두 허용** | `allow_all` | 모든 세션이 제한 없이 동시에 유효합니다. |
| **단일** | `single` | 하나의 활성 세션만. 새 로그인은 이전 세션을 무효화합니다. |
| **최대 N** | `max:3` | 최대 N개의 활성 세션. 초과 시 가장 오래된 세션이 제거됩니다. |
| **알림** | `notify` | 모든 세션이 유효하지만, 사용자에게 다른 세션에 대해 알립니다. |

#### **9.2. 구현**

사용자가 로그인하고 정책이 세션 수를 제한할 때:
```
1. 사용자가 로그인 -> 서버가 이 `prn`에 대한 활성 세션 수를 확인
2. 카운트 >= 제한인 경우:
   a. "single" 정책: 모든 이전 세션을 철회하고 새 세션을 생성
   b. "max:n" 정책: 가장 오래된 세션(FIFO)을 철회하고 새 세션을 생성
3. DB에 새 세션 레코드 생성
4. StateProof 및 BearerPass 반환
```

#### **9.3. 세션 알림**

`notify` 정책의 경우, 서버는 활성 세션을 볼 수 있는 엔드포인트를 제공해야 합니다:

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

응답:
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

### **10. 다중 플랫폼 지원**

#### **10.1. 웹 플랫폼 (기본값)**

웹 애플리케이션의 경우, `StateProof`는 섹션 4.3에 따라 `HttpOnly` 쿠키에 저장됩니다.

#### **10.2. 모바일/네이티브 플랫폼**

쿠키가 실용적이지 않은 네이티브 모바일 및 데스크톱 애플리케이션의 경우:

**저장소:**
-   **iOS:** Keychain Services와 `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences 또는 Keystore System
-   **데스크톱:** OS 자격 증명 관리자 (Windows Credential Vault, macOS Keychain)

**StateProof 제출:**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**비쿠키에 대한 추가 요구 사항:**
-   `StateProof`는 클라이언트에 저장될 때 암호화되어야 합니다.
-   `X-JTS-StateProof` 헤더가 있는 요청은 확인을 위해 `X-JTS-Device-ID`를 포함해야 합니다.
-   서버는 `Device-ID`가 초기 인증 중에 등록된 것과 일치하는지 확인해야 합니다.

#### **10.3. 서버 대 서버 (M2M)**

기계 간 통신의 경우:

-   `StateProof`는 사용되지 않습니다 ("사용자 세션" 개념 없음).
-   `BearerPass`는 더 긴 `exp`로 발급됩니다 (권장: 1시간).
-   `prn` 클레임은 사용자가 아닌 서비스/기계 식별자를 포함합니다.
-   `atm` 클레임은 `client_credentials`로 설정됩니다.

**M2M 페이로드 예시:**
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

### **11. 결론**

야누스 토큰 시스템(JTS)은 상태 비저장 검증의 고성능과 상태 저장 세션 관리의 엄격한 보안 제어를 결합한 균형 잡힌 인증 프레임워크를 제공합니다. 2요소 아키텍처, 명확한 용어, 유연한 운영 프로필을 통해 JTS는 차세대 애플리케이션을 위한 강력하고 안전한 인증 표준으로 설계되었습니다.

**다양한 요구에 맞는 세 가지 프로필:**

| 프로필 | 사용 사례 | 복잡성 | 보안 |
| :--- | :--- | :--- | :--- |
| **JTS-L (라이트)** | MVP, 내부 도구, 간단한 앱 | ⭐ 낮음 | ⭐⭐ 기본 |
| **JTS-S (표준)** | 프로덕션 앱, 공개 API | ⭐⭐ 중간 | ⭐⭐⭐⭐ 높음 |
| **JTS-C (기밀성)**| 핀테크, 헬스케어, 고보안 | ⭐⭐⭐ 높음 | ⭐⭐⭐⭐⭐ 최대 |

**이전 세대 토큰 시스템에 대한 JTS의 장점:**
1.  **즉시 철회:** `StateProof` 관리 및 토큰 순환을 통해 (JTS-S/C).
2.  **토큰 도난 감지:** 재생을 감지하는 순환 메커니즘을 통해 (JTS-S/C).
3.  **계층화된 보호:** CSRF 보호, 장치 바인딩 및 선택적 암호화.
4.  **오류 표준화:** 디버깅 및 처리를 위한 일관된 오류 코드.
5.  **플랫폼 유연성:** 웹, 모바일 및 서버 대 서버 지원.
6.  **키 관리:** 다운타임 없는 명확한 키 순환 절차.
7.  **점진적 향상:** 애플리케이션이 성장함에 따라 JTS-L → JTS-S → JTS-C로의 명확한 마이그레이션 경로.

---

### **부록 A: 구현 체크리스트**

구현자는 JTS 준수를 위해 다음 체크리스트를 충족해야 합니다:

#### **JTS-L (라이트) 체크리스트:**

**필수 (MUST):**
- [ ] 비대칭 암호화 사용 (RS256, ES256 등)
- [ ] 모든 BearerPass 헤더에 `kid` 포함
- [ ] StateProof를 SameSite=Strict인 HttpOnly 쿠키에 저장
- [ ] `/renew` 및 `/logout` 엔드포인트에서 CSRF 확인
- [ ] 표준 형식에 따라 오류 응답 반환 (하위 집합)

**권장 (SHOULD):**
- [ ] StateProof 만료를 최대 24시간으로 설정
- [ ] `/renew`에 속도 제한 구현
- [ ] 모든 갱신 활동 기록

---

#### **JTS-S (표준) 체크리스트:**

**필수 (MUST):**
- [ ] 비대칭 암호화 사용 (RS256, ES256 등)
- [ ] 모든 BearerPass 헤더에 `kid` 포함
- [ ] StateProof를 SameSite=Strict인 HttpOnly 쿠키에 저장
- [ ] 모든 `/renew`에서 StateProof 순환 구현
- [ ] 재생을 감지하고 감지 시 세션 철회
- [ ] `/renew` 및 `/logout` 엔드포인트에서 CSRF 확인
- [ ] 표준 형식에 따라 오류 응답 반환 (전체)

**권장 (SHOULD):**
- [ ] 장치 지문(`dfp`) 구현
- [ ] 진행 중인 요청에 대한 유예 기간 지원
- [ ] 가시성을 위해 `/sessions` 엔드포인트 제공
- [ ] 동시 세션 정책 구현
- [ ] 이상 감지 시 보안 알림 전송

**선택 사항 (MAY):**
- [ ] 검사 엔드포인트 구현
- [ ] `org` 클레임으로 다중 테넌시 지원

---

#### **JTS-C (기밀성) 체크리스트:**

**필수 (MUST):**
- [ ] 모든 JTS-S 요구 사항
- [ ] JWE 암호화 구현 (서명 후 암호화)
- [ ] 서명 키와 별도로 암호화 키 관리

**선택 사항 (MAY):**
- [ ] 여러 리소스 서버 암호화 키 지원
- [ ] 암호화 키에 대한 키 교환 프로토콜 구현

---

### **부록 B: 전체 흐름 예시**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        JTS 인증 흐름                                         │
└─────────────────────────────────────────────────────────────────────────────┘

[사용자]        [클라이언트 앱]      [인증 서버]          [리소스 서버]
   │                 │                     │                      │
   │─── 로그인 ──────>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (자격 증명)     │                      │
   │                 │                     │── 세션 생성 ────>│ [DB]
   │                 │                     │<─ 세션 레코드 ─────│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (본문) │                      │
   │                 │    StateProof (쿠키)                       │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    서명 확인   │
   │                 │                     │    (상태 비저장)      │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── 데이터 ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass 만료 ...          │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (StateProof 쿠키)                       │
   │                 │                     │── SP_v1 확인 ────>│ [DB]
   │                 │                     │<─ 유효, 소비됨 ─────│
   │                 │                     │── SP_v2 저장 ──────>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    새 BearerPass    │                      │
   │                 │    StateProof_v2 (쿠키)                    │
   │                 │                     │                      │
   │─── 로그아웃 ─────>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (StateProof 쿠키)                       │
   │                 │                     │── 세션 삭제 ────>│ [DB]
   │                 │<── 200 OK ─────────│                      │
   │<── 로그아웃됨 ───│                     │                      │
   │                 │                     │                      │
```

---

### **부록 C: 참고 자료**

-   RFC 7519 - JSON 웹 토큰 (JWT)
-   RFC 7515 - JSON 웹 서명 (JWS)
-   RFC 7516 - JSON 웹 암호화 (JWE)
-   RFC 7517 - JSON 웹 키 (JWK)
-   RFC 6749 - OAuth 2.0 인증 프레임워크
-   OWASP 세션 관리 치트 시트
-   OWASP 교차 사이트 요청 위조 방지 치트 시트
