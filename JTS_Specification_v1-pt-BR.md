
# Documento de Arquivo do Projeto: Sistema de Token Janus (JTS)

**Título:** Sistema de Token Janus (JTS): Uma Arquitetura de Dois Componentes para Autenticação de API Segura, Revogável e Confidencial

**Status:** Rascunho de Padrão, Versão 1.1

**Autor/Pioneiro:** ukungzulfah

**Data de Publicação:** 30 de novembro de 2025

> **Resumo:**
> Este documento define o **Sistema de Token Janus (JTS)**, um novo padrão de autenticação projetado para enfrentar os desafios de segurança e escalabilidade em ecossistemas de aplicações distribuídas modernas (por exemplo, arquitetura de microsserviços). O JTS introduz uma arquitetura de dois componentes que separa fundamentalmente a **prova de acesso de curto prazo (`BearerPass`)** da **prova de sessão de longo prazo (`StateProof`)**. Essa abordagem permite uma verificação de acesso extremamente rápida e *sem estado* (stateless), ao mesmo tempo que retém a capacidade vital para o gerenciamento de sessão *com estado* (stateful), incluindo a revogação instantânea de sessão. Este documento define três perfis operacionais: **JTS-S (Padrão)** para integridade total com recursos de segurança completos, **JTS-L (Leve)** para implementação leve com complexidade mínima, e **JTS-C (Confidencialidade)** para confidencialidade total da carga útil. Esta especificação também introduz uma nova terminologia de claims para substituir termos legados menos intuitivos.

---

### **Licença de Direitos Autorais**
> Copyright © 2025, ukungzulfah. Todos os Direitos Reservados.
>
> A permissão é concedida, gratuitamente, a qualquer pessoa que obtenha uma cópia desta especificação e da documentação associada ("o Software"), para usar, copiar, modificar, mesclar, publicar, distribuir e/ou vender cópias do Software, sujeita às seguintes condições:
>
> O aviso de direitos autorais acima e este aviso de permissão devem ser incluídos em todas as cópias ou partes substanciais do Software. O SOFTWARE É FORNECIDO "COMO ESTÁ", SEM GARANTIA DE QUALQUER TIPO, EXPRESSA OU IMPLÍCITA.

---

### **1. Introdução**

#### **1.1. Desafios da Autenticação Moderna**
Na arquitetura de software moderna, as aplicações são divididas em serviços pequenos e independentes (microsserviços). Este modelo exige um sistema de autenticação que seja leve, descentralizado e que não dependa de uma única sessão centralizada e monolítica.

#### **1.2. Limitações dos Modelos de Token sem Estado de Primeira Geração**
Os modelos de autenticação baseados em tokens sem estado de primeira geração forneceram uma solução parcial, mas introduziram fraquezas significativas:
1.  **Vulnerabilidade de Revogação de Sessão:** Tokens emitidos не podem ser invalidados à força do lado do servidor antes de seu tempo de expiração.
2.  **Exposição de Informações:** A carga útil do token é frequentemente apenas codificada, não criptografada, de modo que os dados internos podem ser lidos por qualquer parte que possua o token.
3.  **Complexidade no Gerenciamento de Chaves:** O uso de uma chave simétrica compartilhada cria um ponto único de falha de alto risco em um ambiente distribuído.

#### **1.3. Um Novo Paradigma: Sistema de Token Janus (JTS)**
O JTS é proposto como uma evolução para abordar essas fraquezas. Com seu princípio de dualidade, o JTS combina a eficiência *sem estado* com a segurança *com estado*.

### **2. Conceitos Centrais do JTS**

#### **2.1. Princípio da Dualidade**
O JTS separa o papel de um token em dois:
1.  **Acesso:** Conceder permissão para acessar recursos por uma duração muito curta.
2.  **Sessão:** Provar a validade da sessão de autenticação geral do usuário.

#### **2.2. Os Dois Componentes do JTS**
1.  **`BearerPass`:** Um token de acesso de curta duração, assinado criptograficamente. É usado em cada solicitação de API e verificado sem estado.
2.  **`StateProof`:** Um token de sessão de longa duração, opaco и com estado. É usado exclusivamente para obter um novo `BearerPass` e é armazenado de forma segura no lado do cliente. Sua existência no banco de dados do servidor determina a validade de uma sessão.

### **3. Terminologia e Claims do JTS**

Como um refinamento, o JTS introduz uma terminologia de claims mais explícita e intuitiva, afastando-se de termos legados ambíguos.

| Claim JTS | Nome Completo | Descrição | Substitui |
| :--- | :--- | :--- | :--- |
| **`prn`** | **Principal** | Identificador único para o principal autenticado (geralmente um usuário). | `sub` |
| **`aid`** | **Anchor ID** | Um ID único que "ancora" o `BearerPass` ao registro de sessão no servidor. | `sid` |
| **`tkn_id`**| **Token ID** | Um identificador único para cada `BearerPass`, prevenindo ataques de repetição. | `jti` |
| `exp` | Expiration Time | Tempo de expiração do token (mantido da RFC 7519). | - |
| `aud` | Audience | O destinatário pretendido para este token (mantido da RFC 7519). | - |
| `iat` | Issued At | O momento em que o token foi emitido (mantido da RFC 7519). | - |

#### **3.2. Claims Estendidas**

O JTS define claims adicionais para uma segurança e funcionalidade mais robustas:

| Claim JTS | Nome Completo | Descrição | Requerido |
| :--- | :--- | :--- | :--- |
| **`dfp`** | **Device Fingerprint** | Hash das características do dispositivo para vincular o token a um dispositivo específico. | Não |
| **`perm`**| **Permissions** | Uma matriz de strings que definem as permissões/escopos que o token possui. | Não |
| **`grc`** | **Grace Period** | Tolerância de tempo (em segundos) após `exp` para solicitações em trânsito. | Não |
| **`org`** | **Organization** | Identificador de inquilino/organização para sistemas multi-inquilino. | Não |
| **`atm`** | **Auth Method** | Método de autenticação usado (ex: `pwd`, `mfa:totp`, `sso`). | Não |
| **`ath`** | **Auth Time** | Timestamp Unix de quando o usuário realizou uma autenticação ativa pela última vez. | Não |
| **`spl`** | **Session Policy** | A política de sessão concorrente em vigor (`allow_all`, `single`, `max:n`). | Não |

**Exemplo de Carga Útil com Claims Estendidas:**
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

### **4. Perfil Padrão: JTS-S (Integridade)**

Este perfil foca em velocidade, integridade e capacidades de revogação de sessão.

#### **4.1. Estrutura do `BearerPass` (Formato JWS)**
O `BearerPass` no perfil JTS-S é uma **Assinatura Web JSON (JWS)** assinada com **criptografia assimétrica (ex: RS256)**.

**Exemplo de Cabeçalho:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Nota:** A claim `kid` (ID da Chave) é OBRIGATÓRIA para suportar a rotação de chaves (ver Seção 7).

**Exemplo de Carga Útil:**
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

#### **4.2. Fluxo de Trabalho**
1.  **Autenticação:** O usuário faz login -> O servidor cria um registro de sessão no BD, gerando um `StateProof` (armazenado no BD) e um `BearerPass` (JWS). O `StateProof` é enviado via um cookie `HttpOnly`, o `BearerPass` via o corpo JSON.
2.  **Acesso a Recursos:** O cliente envia o `BearerPass` no cabeçalho -> O servidor verifica a assinatura JWS usando a chave pública.
3.  **Renovação:** O `BearerPass` expira -> O cliente chama o endpoint `/renew` com o `StateProof` no cookie -> O servidor valida o `StateProof` no BD; se válido, emite um novo `BearerPass`.
4.  **Revogação (Logout):** O cliente chama `/logout` -> O servidor deleta o registro de sessão associado ao `StateProof` do BD. A sessão torna-se imediatamente inválida.

#### **4.3. Requisitos de Cookies e Proteção CSRF**

O `StateProof` armazenado em um cookie DEVE atender aos seguintes requisitos de segurança:

**Atributos de Cookie OBRIGATÓRIOS:**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| Atributo | Valor | Descrição |
| :--- | :--- | :--- |
| `HttpOnly` | OBRIGATÓRIO | Previne o acesso a partir de JavaScript (mitiga XSS). |
| `Secure` | OBRIGATÓRIO | O cookie só é enviado via HTTPS. |
| `SameSite` | `Strict` | Previne o envio do cookie em solicitações entre sites (mitiga CSRF). |
| `Path` | `/jts` | Limita o cookie para ser enviado apenas aos endpoints do JTS. |
| `Max-Age` | Conforme política | Tempo de vida do cookie de acordo com a política de sessão. |

**Proteção CSRF Adicional:**

Para os endpoints `/renew` e `/logout`, o servidor DEVE validar pelo menos UM dos seguintes mecanismos:

1.  **Validação do Cabeçalho Origin:** Garantir que o cabeçalho `Origin` ou `Referer` venha de um domínio permitido.
2.  **Requisito de Cabeçalho Personalizado:** Exigir um cabeçalho personalizado que не pode ser definido por um envio de formulário padrão:
    ```
    X-JTS-Request: 1
    ```
3.  **Padrão de Cookie de Duplo Envio:** Enviar um valor de token CSRF tanto em um cookie QUANTO no corpo/cabeçalho da solicitação, e então validar que eles correspondem.

#### **4.4. Rotação do StateProof**

Para aumentar a segurança e detectar o roubo de tokens, o JTS EXIGE a rotação do `StateProof` a cada operação de renovação.

**Mecanismo:**
1.  O cliente chama `/renew` com o `StateProof` antigo.
2.  O servidor valida o `StateProof` antigo no banco de dados.
3.  Se válido:
    a.  O servidor DELETA ou MARCA o `StateProof` antigo como *consumido*.
    b.  O servidor emite um NOVO `StateProof` e um novo `BearerPass`.
    c.  O novo `StateProof` é enviado através de um cabeçalho `Set-Cookie`.
4.  Se o `StateProof` antigo já estiver marcado como *consumido* (repetição detectada):
    a.  O servidor DEVE revogar imediatamente TODAS as sessões associadas a esse `aid`.
    b.  O servidor DEVE retornar um erro `JTS-401-05` (Sessão Comprometida).
    c.  O servidor DEVE enviar uma notificação de segurança ao usuário.

**Diagrama de Rotação:**
```
[Cliente]                              [Servidor de Autenticação]     [Banco de Dados]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- Validar StateProof_v1 ---->|
    |                                       |<-- Válido, marcar como consumido ---|
    |                                       |                               |
    |                                       |-- Gerar StateProof_v2 ---->|
    |                                       |<-- Armazenado --------------------|
    |                                       |                               |
    |<-- 200 OK (BearerPass_novo) ----------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**Detecção de Anomalias (Ataque de Repetição):**
```
[Atacante]                            [Servidor de Autenticação]     [Banco de Dados]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (token roubado)              |
    |                                       |-- Validar StateProof_v1 ---->|
    |                                       |<-- CONSUMIDO! Repetição detectada -|
    |                                       |                               |
    |                                       |-- REVOGAR todas as sessões (aid) ->|
    |                                       |<-- Feito ----------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (Comprometido) ------|
    |                                       |                               |
```

#### **4.5. Lidando com Condições de Corrida em Renovações Concorrentes**

Em cenários onde um usuário tem múltiplas abas/janelas ou as solicitações de renovação ocorrem quase simultaneamente, existe o risco de uma detecção de repetição *falsa positiva*. O JTS define um mecanismo de **Janela de Graça de Rotação** para lidar com esta condição.

**Problema:**
```
[Aba A]                                [Servidor de Autenticação]     [Banco de Dados]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Marcar SP_v1 como consumido -->|
    |                                     |                               |
[Aba B]  (ligeiramente atrasada)         |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Verificar SP_v1 -------------->|
    |                                     |<-- CONSUMIDO! (falso positivo) |
    |<-- 401 JTS-401-05 ??? --------------|  (usuário não comprometido!)    |
```

**Solução: Janela de Graça de Rotação**

O servidor DEVE implementar uma **janela de graça de rotação** com as seguintes especificações:

1.  **Duração da Janela de Graça:** O servidor DEVE armazenar o `previous_state_proof` por **5-10 segundos** após uma rotação.
2.  **Validação Dupla:** Durante a janela de graça, o servidor DEVE aceitar TANTO o `current_state_proof` QUANTO o `previous_state_proof`.
3.  **Resposta para o Token Anterior:** Se uma solicitação usa um `previous_state_proof` que ainda está dentro da janela de graça:
    -   O servidor DEVE retornar o MESMO `StateProof` e `BearerPass` que já foram gerados para o `current_state_proof`.
    -   O servidor NÃO DEVE gerar novos tokens (previne a divergência de tokens).
4.  **Após a Janela de Graça:** Uma solicitação com um `previous_state_proof` que passou da janela de graça DEVE ser tratada como um ataque de repetição.

**Implementação do Banco de Dados:**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- Token anterior
    rotation_timestamp    TIMESTAMP,              -- Quando a última rotação ocorreu
    -- ... outras colunas
);
```

**Lógica de Validação:**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 seconds
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // Retornar tokens existentes
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**Diagrama de Renovação Concorrente (Tratado):**
```
[Aba A]                                [Servidor de Autenticação]     [Banco de Dados]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Rotacionar: SP_v1 -> SP_v2 ->|
    |                                     |   (armazenar previous=SP_v1)    |
    |<-- 200 OK (BP_novo, SP_v2) ----------|                               |
    |                                     |                               |
[Aba B]  (dentro de 10 segundos)         |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Verificar SP_v1 -------------->|
    |                                     |<-- Encontrado em previous_sp,    |
    |                                     |    dentro da janela de graça ----|
    |<-- 200 OK (BP_novo, SP_v2) ----------|  (mesmos tokens da Aba A)     |
    |                                     |                               |
```

> **Nota:** Ambas as abas agora têm o mesmo `StateProof` (SP_v2), permanecendo assim sincronizadas.

#### **4.6. Período de Graça para Solicitações em Trânsito**

Para lidar com condições de corrida onde um `BearerPass` expira enquanto uma solicitação está em trânsito:

**Especificação:**
-   Um Servidor de Recursos PODE fornecer uma tolerância de tempo (*período de graça*) após o tempo `exp`.
-   O período de graça NÃO DEVE exceder **60 segundos**.
-   Se a claim `grc` estiver presente na carga útil, seu valor define o período de graça em segundos.
-   Se a claim `grc` не estiver presente, o período de graça padrão é de **0 segundos** (sem tolerância).

**Lógica de Validação:**
```
current_time = now()
effective_expiry = token.exp + token.grc (or 0 if grc is not present)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**Nota:** O período de graça NÃO estende o tempo de vida do token para fins de auditoria. O tempo `exp` original ainda é usado para registro.

### **5. Perfil Leve: JTS-L (Lite)**

Este perfil é projetado para casos de uso de baixa complexidade que requerem facilidade de implementação sem sacrificar os princípios de segurança centrais do JTS.

#### **5.1. Quando Usar o JTS-L**

O JTS-L é adequado para os seguintes cenários:

| Cenário | Recomendação | Razão |
| :--- | :--- | :--- |
| MVP de Startup / Protótipo | ✅ JTS-L | Rápido de implementar, pode ser atualizado para JTS-S mais tarde. |
| Ferramentas Internas / Painel de Admin | ✅ JTS-L | Base de usuários pequena, risco menor. |
| Aplicação de Página Única Simples | ✅ JTS-L | Não precisa de detecção de repetição complexa. |
| API Pública com dados sensíveis | ❌ Usar JTS-S | Precisa de proteção contra repetição e vinculação de dispositivo. |
| Fintech / Saúde | ❌ Usar JTS-S/C | Conformidade e segurança máximas são necessárias. |
| SaaS Multi-inquilino | ❌ Usar JTS-S | Precisa de isolamento e trilhas de auditoria completas. |

#### **5.2. Principais Diferenças do JTS-S**

| Característica | JTS-S (Padrão) | JTS-L (Leve) |
| :--- | :--- | :--- |
| Rotação do StateProof | ✅ OBRIGATÓRIA a cada `/renew` | ❌ OPCIONAL |
| Detecção de Repetição | ✅ Embutida via marcação de consumido | ⚠️ Manual / nenhuma |
| Impressão Digital do Dispositivo (`dfp`) | ✅ Recomendado | ❌ Não requerido |
| Período de Graça (`grc`) | ✅ Suportado | ✅ Suportado |
| Claims Estendidas | ✅ Completo | ⚠️ Subconjunto mínimo |
| Política de Sessão Concorrente | ✅ Completa | ⚠️ Apenas `allow_all` |
| Complexidade do Banco de Dados | Alta (rastreamento de tokens consumidos) | Baixa (tabela de sessão simples) |
| Códigos de Erro | Completo (todos os códigos) | Subconjunto essencial |

#### **5.3. Estrutura do `BearerPass` no JTS-L**

O `BearerPass` no JTS-L ainda usa **JWS com criptografia assimétrica**, mas com uma carga útil mais minimalista.

**Cabeçalho:**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Carga Útil Mínima:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**Nota:** A claim `tkn_id` é **OPCIONAL** no JTS-L porque a detecção de repetição não é necessária.

#### **5.4. Fluxo de Trabalho do JTS-L (Simplificado)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FLUXO SIMPLIFICADO DO JTS-L                             │
└─────────────────────────────────────────────────────────────────────────────┘

[Cliente]                              [Servidor de Autenticação]     [Banco de Dados]
    │                                       │                               │
    │── POST /login (credenciais) ─────────>│                               │
    │                                       │── Criar Sessão ────────────>│
    │                                       │<── ID da Sessão ───────────────│
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass (corpo)                 │                               │
    │    StateProof (cookie)                │                               │
    │                                       │                               │
    │   ... BearerPass expira ...          │                               │
    │                                       │                               │
    │── POST /renew (StateProof) ──────────>│                               │
    │                                       │── Verificar se a Sessão Existe ->│
    │                                       │<── Válido ─────────────────────│
    │                                       │   (SEM rotação, SEM consumido) │
    │<── 200 OK ────────────────────────────│                               │
    │    BearerPass_novo (corpo)            │                               │
    │    (StateProof inalterado)            │                               │
    │                                       │                               │
```

**Principais Diferenças:**
-   O `StateProof` **NÃO é rotacionado** a cada `/renew`—o mesmo token pode ser usado várias vezes enquanto a sessão estiver ativa.
-   O servidor só precisa verificar se o registro da sessão **existe** no banco de dados, sem precisar rastrear um status "consumido".
-   A complexidade do banco de dados é significativamente reduzida.

#### **5.5. Esquema do Banco de Dados do JTS-L**

O banco de dados para o JTS-L é muito mais simples:

```sql
-- JTS-L: Tabela de Sessão Simples
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- Anchor ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- Principal (ID do Usuário)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- Opcional: para lista de sessões
    ip_address      VARCHAR(45)               -- Opcional: para auditoria
);

-- Índice para consulta por usuário
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**Compare com o JTS-S que requer:**
```sql
-- JTS-S: Tabela de Sessão Completa com Rastreamento de Rotação
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- Para janela de graça
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- Detecção de repetição
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... mais colunas
);

-- Tabela adicional para rastrear tokens consumidos
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. Subconjunto de Códigos de Erro para o JTS-L**

O JTS-L só é OBRIGADO a implementar o seguinte subconjunto de códigos de erro:

| Código de Erro | Chave de Erro | Descrição |
| :--- | :--- | :--- |
| `JTS-400-01` | `malformed_token` | O token não pôde ser analisado. |
| `JTS-401-01` | `bearer_expired` | O BearerPass expirou. |
| `JTS-401-02` | `signature_invalid` | A assinatura é inválida. |
| `JTS-401-03` | `stateproof_invalid` | O StateProof é inválido. |
| `JTS-401-04` | `session_terminated` | A sessão foi encerrada. |

**Os seguintes códigos de erro NÃO são necessários no JTS-L:**
-   `JTS-401-05` (session_compromised) — sem detecção de repetição
-   `JTS-401-06` (device_mismatch) — sem vinculação de dispositivo
-   `JTS-403-03` (org_mismatch) — sem suporte multi-inquilino

#### **5.7. Migrando do JTS-L para o JTS-S**

O JTS-L é projetado para ser facilmente atualizável para o JTS-S à medida que as necessidades de segurança aumentam:

**Passos de Migração:**

1.  **Atualizar o Tipo de Cabeçalho:**
    ```json
    // Antes
    { "typ": "JTS-L/v1" }
    // Depois
    { "typ": "JTS-S/v1" }
    ```

2.  **Adicionar Colunas ao Banco de Dados:**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **Implementar Rotação do StateProof:** Atualizar a lógica do `/renew` para gerar um novo StateProof.

4.  **Adicionar `tkn_id` à Carga Útil:** Começar a gerar um ID de token único para cada BearerPass.

5.  **Lançamento Gradual:**
    -   Fase 1: O servidor aceita tokens JTS-L e JTS-S
    -   Fase 2: Todos os novos tokens são JTS-S
    -   Fase 3: Rejeitar tokens JTS-L após o tempo máximo de vida da sessão

#### **5.8. Limitações e Riscos do JTS-L**

> ⚠️ **AVISO:** Os implementadores DEVEM entender os seguintes riscos antes de escolher o JTS-L:

| Risco | Impacto | Mitigação |
| :--- | :--- | :--- |
| **Sem detecção de repetição** | Um StateProof roubado pode ser usado várias vezes sem ser detectado. | Usar um `exp` mais curto para a sessão. |
| **Sem vinculação de dispositivo** | O token pode ser usado de um dispositivo diferente. | Implementar limitação de taxa baseada em IP. |
| **O roubo не é detectado** | O usuário não será notificado se seu token for roubado. | Monitorar padrões de login, notificar sobre novo IP. |

**Recomendações de Mitigação para o JTS-L:**
-   Definir uma expiração de `StateProof` mais curta (máx. 24 horas vs. 7 dias no JTS-S)
-   Implementar limitação de taxa no endpoint `/renew`
-   Registrar toda a atividade de renovação para auditoria manual
-   Considerar notificações por e-mail para logins de um novo IP/localização

---

### **6. Perfil de Confidencialidade: JTS-C (Confidentiality)**

Este perfil adiciona uma camada de criptografia para confidencialidade total da carga útil.

#### **6.1. Estrutura do `BearerPass` (Formato JWE)**
O `BearerPass` no perfil JTS-C é uma **Criptografia Web JSON (JWE)**. O token JWS do perfil padrão é "envelopado" ou criptografado em um JWE.

#### **6.2. Fluxo de Trabalho**
*   **Criação de Token ("Assinado e depois Criptografado"):**
    1.  Criar um JWS como no perfil JTS-S.
    2.  Criptografar todo o JWS usando a **chave pública do Servidor de Recursos pretendido**. O resultado é um JWE.
*   **Verificação de Token ("Decriptado e depois Verificado"):**
    1.  O Servidor de Recursos recebe o JWE.
    2.  O servidor decripta o JWE usando sua **própria chave privada**. O resultado é o JWS original.
    3.  O servidor verifica o JWS usando a **chave pública do Servidor de Autenticação**.

### **7. Análise de Segurança e Tratamento de Erros**

#### **7.1. Análise de Segurança**

*   **Revogação de Sessão:** Totalmente resolvido através do gerenciamento do `StateProof` no banco de dados do servidor.
*   **Vazamento de Credenciais:** Minimizado pelo uso obrigatório de criptografia assimétrica e pela proteção do `StateProof` em um cookie `HttpOnly`.
*   **Vazamento de Informações:** Minimizado no JTS-S/JTS-L com uma carga útil minimalista e totalmente resolvido no JTS-C através da criptografia JWE.
*   **Ataques de Repetição:** Mitigado com um `tkn_id` único e a **rotação do StateProof** no JTS-S. **Nota:** O JTS-L não fornece proteção automática contra repetição.
*   **Ataques XSS:** O risco de roubo do token de sessão `StateProof` é significativamente reduzido devido à flag `HttpOnly` no cookie.
*   **Ataques CSRF:** Mitigado por uma combinação de `SameSite=Strict` e validação de cabeçalho adicional.
*   **Roubo de Token:** Mitigado com **Impressão Digital do Dispositivo (`dfp`)** no JTS-S. **Nota:** O JTS-L não suporta vinculação de dispositivo.

#### **7.2. Códigos de Erro Padrão**

O JTS define códigos de erro padrão para consistência de implementação e facilidade de depuração:

**Formato de Resposta de Erro:**
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

**Lista de Códigos de Erro:**

| Código de Erro | Status HTTP | Chave de Erro | Descrição | Ação |
| :--- | :--- | :--- | :--- | :--- |
| `JTS-400-01` | 400 | `malformed_token` | O token не pôde ser analisado ou tem um formato inválido. | `reauth` |
| `JTS-400-02` | 400 | `missing_claims` | Claims necessárias estão faltando no token. | `reauth` |
| `JTS-401-01` | 401 | `bearer_expired` | O BearerPass expirou. | `renew` |
| `JTS-401-02` | 401 | `signature_invalid` | A assinatura do BearerPass é inválida. | `reauth` |
| `JTS-401-03` | 401 | `stateproof_invalid` | O StateProof é inválido ou não encontrado no BD. | `reauth` |
| `JTS-401-04` | 401 | `session_terminated` | A sessão foi encerrada (logout ou política concorrente). | `reauth` |
| `JTS-401-05` | 401 | `session_compromised`| Um ataque de repetição foi detectado; todas as sessões são revogadas.| `reauth` |
| `JTS-401-06` | 401 | `device_mismatch` | A impressão digital do dispositivo не corresponde. | `reauth` |
| `JTS-403-01` | 403 | `audience_mismatch` | O token não é destinado a este recurso. | `none` |
| `JTS-403-02` | 403 | `permission_denied` | O token não tem as permissões necessárias. | `none` |
| `JTS-403-03` | 403 | `org_mismatch` | O token pertence a uma organização/inquilino diferente. | `none` |
| `JTS-500-01` | 500 | `key_unavailable` | A chave pública para verificação não está disponível. | `retry` |

**Valores de Ação:**
-   `renew`: O cliente deve chamar o endpoint `/renew` para obter um novo BearerPass.
-   `reauth`: O usuário deve se autenticar novamente (fazer login).
-   `retry`: A solicitação pode ser tentada novamente após `retry_after` segundos.
-   `none`: Nenhuma ação pode corrigir esta condição.

### **8. Gerenciamento de Chaves**

#### **8.1. Requisito de ID da Chave**

Cada `BearerPass` DEVE incluir uma claim `kid` (ID da Chave) no cabeçalho para identificar a chave usada para assinar.

**Formato de Cabeçalho com kid:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. Procedimento de Rotação de Chaves**

Para substituir uma chave de assinatura sem invalidar os tokens já emitidos:

**Passos:**
1.  **Gerar Novo Par de Chaves:** Criar um novo par de chaves com um `kid` único.
2.  **Publicar Chave Pública:** Adicionar a nova chave pública ao endpoint JWKS. O servidor DEVE suportar múltiplas chaves públicas ativas.
3.  **Começar a Assinar com a Nova Chave:** Todos os novos tokens `BearerPass` são assinados com a nova chave.
4.  **Aposentar Chave Antiga:** Após `max_bearer_lifetime` + buffer (recomendação: 15 minutos), remover a chave pública antiga do JWKS.

**Resposta do Endpoint JWKS:**
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

**Nota:** O campo `exp` em uma entrada de chave indica quando a chave será aposentada (opcional, para informação do cliente).

#### **8.3. Endpoint JWKS Padrão**

O JTS define um caminho padrão para o endpoint JWKS (Conjunto de Chaves Web JSON) para que os Servidores de Recursos possam encontrar consistentemente as chaves públicas.

**Caminho Padrão:**
```
GET /.well-known/jts-jwks
```

**Requisitos:**

| Aspecto | Especificação |
| :--- | :--- |
| **Caminho** | `/.well-known/jts-jwks` (OBRIGATÓRIO) |
| **Método** | `GET` |
| **Autenticação** | Não necessária (endpoint público) |
| **Content-Type** | `application/json` |
| **CORS** | DEVE permitir solicitações de origem cruzada de domínios válidos |

**Cache:**

O servidor DEVE incluir cabeçalhos de cache apropriados:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| Cabeçalho | Valor Recomendado | Descrição |
| :--- | :--- | :--- |
| `Cache-Control` | `max-age=3600` | Armazenar em cache por 1 hora. |
| `stale-while-revalidate`| `60` | Permitir uma resposta obsoleta por 60 segundos enquanto revalida. |
| `ETag` | Hash do conteúdo do JWKS | Para solicitações condicionais. |

**Descoberta (Opcional):**

Para suportar a auto-descoberta, o Servidor de Autenticação PODE fornecer um endpoint de metadados:

```
GET /.well-known/jts-configuration
```

**Resposta:**
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

#### **8.4. Algoritmos Suportados**

O JTS recomenda os seguintes algoritmos:

| Algoritmo | Tipo | Recomendação | Notas |
| :--- | :--- | :--- | :--- |
| `RS256` | Assimétrico | RECOMENDADO | RSA com SHA-256, amplamente suportado. |
| `RS384` | Assimétrico | SUPORTADO | RSA com SHA-384. |
| `RS512` | Assimétrico | SUPORTADO | RSA com SHA-512. |
| `ES256` | Assimétrico | RECOMENDADO | ECDSA com P-256, mais eficiente. |
| `ES384` | Assimétrico | SUPORTADO | ECDSA com P-384. |
| `ES512` | Assimétrico | SUPORTADO | ECDSA com P-521. |
| `PS256` | Assimétrico | SUPORTADO | RSASSA-PSS com SHA-256. |
| `HS256` | Simétrico | **NÃO PERMITIDO** | Não se alinha com os princípios do JTS. |
| `HS384` | Simétrico | **NÃO PERMITIDO** | Não se alinha com os princípios do JTS. |
| `HS512` | Simétrico | **NÃO PERMITIDO** | Não se alinha com os princípios do JTS. |
| `none` | - | **PROIBIDO** | Sem assinatura, altamente inseguro. |

### **9. Política de Sessão Concorrente**

O JTS define políticas para lidar com situações em que um único usuário tem múltiplas sessões ativas.

> **Nota:** As políticas de sessão concorrente aplicam-se apenas ao **JTS-S** e **JTS-C**. O perfil **JTS-L** suporta apenas a política `allow_all` por padrão.

#### **9.1. Opções de Política**

| Política | Claim `spl` | Comportamento |
| :--- | :--- | :--- |
| **Permitir Todas** | `allow_all` | Todas as sessões são válidas simultaneamente sem limites. |
| **Única** | `single` | Apenas uma sessão ativa. Um novo login invalida a antiga. |
| **Máx N** | `max:3` | Máximo de N sessões ativas. A mais antiga é despejada se excedido. |
| **Notificar** | `notify` | Todas as sessões são válidas, mas o usuário é notificado sobre as outras. |

#### **9.2. Implementação**

Quando um usuário faz login e a política limita o número de sessões:
```
1. Usuário faz login -> Servidor verifica o número de sessões ativas para este `prn`
2. Se contagem >= limite:
   a. Política "single": Revogar todas as sessões antigas, criar uma nova
   b. Política "max:n": Revogar a sessão mais antiga (FIFO), criar uma nova
3. Criar novo registro de sessão no BD
4. Retornar StateProof e BearerPass
```

#### **9.3. Notificação de Sessão**

Para a política `notify`, o servidor DEVE fornecer um endpoint para visualizar as sessões ativas:

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

Resposta:
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

### **10. Suporte Multiplataforma**

#### **10.1. Plataforma Web (Padrão)**

Para aplicações web, o `StateProof` é armazenado em um cookie `HttpOnly` conforme a Seção 4.3.

#### **10.2. Plataformas Móveis/Nativas**

Para aplicações móveis e de desktop nativas onde os cookies не são práticos:

**Armazenamento:**
-   **iOS:** Keychain Services com `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences ou Keystore System
-   **Desktop:** Gerenciador de Credenciais do SO (Windows Credential Vault, macOS Keychain)

**Submissão do StateProof:**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**Requisitos Adicionais para Não-Cookie:**
-   O `StateProof` DEVE ser criptografado quando armazenado no cliente.
-   As solicitações com o cabeçalho `X-JTS-StateProof` DEVEM incluir um `X-JTS-Device-ID` para validação.
-   O servidor DEVE validar que o `Device-ID` corresponde ao registrado durante a autenticação inicial.

#### **10.3. Servidor a Servidor (M2M)**

Para comunicação de máquina a máquina:

-   `StateProof` NÃO é usado (não há conceito de "sessão do usuário").
-   `BearerPass` é emitido com um `exp` mais longo (recomendação: 1 hora).
-   A claim `prn` contém um identificador de serviço/máquina, não um usuário.
-   A claim `atm` é definida como `client_credentials`.

**Exemplo de Carga Útil M2M:**
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

### **11. Conclusão**

O Sistema de Token Janus (JTS) oferece um framework de autenticação equilibrado, combinando o alto desempenho da verificação sem estado com os rigorosos controles de segurança do gerenciamento de sessão com estado. Com sua arquitetura de dois componentes, terminologia clara e perfis operacionais flexíveis, o JTS é projetado para ser um padrão de autenticação robusto e seguro para a próxima geração de aplicações.

**Três Perfis para Várias Necessidades:**

| Perfil | Caso de Uso | Complexidade | Segurança |
| :--- | :--- | :--- | :--- |
| **JTS-L (Leve)** | MVP, Ferramentas Internas, Apps Simples | ⭐ Baixa | ⭐⭐ Básica |
| **JTS-S (Padrão)** | Apps de Produção, APIs Públicas | ⭐⭐ Média | ⭐⭐⭐⭐ Alta |
| **JTS-C (Confidencialidade)**| Fintech, Saúde, Alta Segurança | ⭐⭐⭐ Alta | ⭐⭐⭐⭐⭐ Máxima |

**Vantagens do JTS sobre sistemas de tokens de gerações anteriores:**
1.  **Revogação Instantânea:** Através do gerenciamento do `StateProof` e rotação de tokens (JTS-S/C).
2.  **Detecção de Roubo de Token:** Através de um mecanismo de rotação que detecta repetição (JTS-S/C).
3.  **Proteção em Camadas:** Proteção CSRF, vinculação de dispositivo e criptografia opcional.
4.  **Padronização de Erros:** Códigos de erro consistentes para depuração e tratamento.
5.  **Flexibilidade de Plataforma:** Suporte para web, móvel e servidor a servidor.
6.  **Gerenciamento de Chaves:** Procedimento claro de rotação de chaves sem tempo de inatividade.
7.  **Melhoria Progressiva:** Um caminho de migração claro de JTS-L → JTS-S → JTS-C à medida que uma aplicação cresce.

---

### **Apêndice A: Lista de Verificação de Implementação**

Os implementadores DEVEM atender à seguinte lista de verificação para conformidade com o JTS:

#### **Lista de Verificação do JTS-L (Leve):**

**Requerido (DEVE):**
- [ ] Usar criptografia assimétrica (RS256, ES256, etc.)
- [ ] Incluir `kid` no cabeçalho de cada BearerPass
- [ ] Armazenar o StateProof em um cookie HttpOnly com SameSite=Strict
- [ ] Validar CSRF nos endpoints `/renew` e `/logout`
- [ ] Retornar respostas de erro de acordo com o formato padrão (subconjunto)

**Recomendado (DEVE):**
- [ ] Definir a expiração do StateProof para um máximo de 24 horas
- [ ] Implementar limitação de taxa em `/renew`
- [ ] Registrar todas as atividades de renovação

---

#### **Lista de Verificação do JTS-S (Padrão):**

**Requerido (DEVE):**
- [ ] Usar criptografia assimétrica (RS256, ES256, etc.)
- [ ] Incluir `kid` no cabeçalho de cada BearerPass
- [ ] Armazenar o StateProof em um cookie HttpOnly com SameSite=Strict
- [ ] Implementar a rotação do StateProof a cada `/renew`
- [ ] Detectar repetição e revogar sessões quando detectado
- [ ] Validar CSRF nos endpoints `/renew` e `/logout`
- [ ] Retornar respostas de erro de acordo com o formato padrão (completo)

**Recomendado (DEVE):**
- [ ] Implementar impressão digital do dispositivo (`dfp`)
- [ ] Suportar períodos de graça para solicitações em trânsito
- [ ] Fornecer um endpoint `/sessions` para visibilidade
- [ ] Implementar políticas de sessão concorrente
- [ ] Enviar notificações de segurança quando anomalias forem detectadas

**Opcional (PODE):**
- [ ] Implementar um endpoint de introspecção
- [ ] Suportar multi-tenancy com a claim `org`

---

#### **Lista de Verificação do JTS-C (Confidencialidade):**

**Requerido (DEVE):**
- [ ] Todos os requisitos do JTS-S
- [ ] Implementar criptografia JWE (assinado e depois criptografado)
- [ ] Gerenciar chaves de criptografia separadamente das chaves de assinatura

**Opcional (PODE):**
- [ ] Suportar múltiplas chaves de criptografia do Servidor de Recursos
- [ ] Implementar um protocolo de troca de chaves para as chaves de criptografia

---

### **Apêndice B: Exemplo de Fluxo Completo**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        FLUXO DE AUTENTICAÇÃO JTS                             │
└─────────────────────────────────────────────────────────────────────────────┘

[Usuário]       [App Cliente]        [Servidor Auth]      [Servidor Recurso]
   │                 │                     │                      │
   │─── Login ──────>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (credenciais)    │                      │
   │                 │                     │── Criar Sessão ────>│ [BD]
   │                 │                     │<─ Registro Sessão ───│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (corpo)│                     │
   │                 │    StateProof (cookie)                     │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    Verificar assinatura│
   │                 │                     │    (sem estado)      │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── Dados ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass expira ...        │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Validar SP_v1 ───>│ [BD]
   │                 │                     │<─ Válido, consumido ──│
   │                 │                     │── Armazenar SP_v2 ──>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass_novo  │                      │
   │                 │    StateProof_v2 (cookie)                  │
   │                 │                     │                      │
   │─── Logout ─────>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Deletar Sessão ───>│ [BD]
   │                 │<── 200 OK ─────────│                      │
   │<── Deslogado ───│                     │                      │
   │                 │                     │                      │
```

---

### **Apêndice C: Referências**

-   RFC 7519 - JSON Web Token (JWT)
-   RFC 7515 - JSON Web Signature (JWS)
-   RFC 7516 - JSON Web Encryption (JWE)
-   RFC 7517 - JSON Web Key (JWK)
-   RFC 6749 - The OAuth 2.0 Authorization Framework
-   OWASP Session Management Cheat Sheet
-   OWASP Cross-Site Request Forgery Prevention Cheat Sheet
