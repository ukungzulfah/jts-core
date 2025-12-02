
# Dokumen Arsip Proyek: Janus Token System (JTS)

**Judul:** Janus Token System (JTS): Arsitektur Dua Komponen untuk Otentikasi API yang Aman, Dapat Dicabut, dan Rahasia

**Status:** Draf Standar, Versi 1.1

**Penulis/Pengembang:** ukungzulfah

**Tanggal Publikasi:** 30 November 2025

> **Abstrak:**
> Dokumen ini mendefinisikan **Janus Token System (JTS)**, sebuah standar otentikasi baru yang dirancang untuk mengatasi tantangan keamanan dan skalabilitas dalam ekosistem aplikasi terdistribusi modern (misalnya, arsitektur layanan mikro). JTS memperkenalkan arsitektur dua komponen yang secara fundamental memisahkan **bukti akses jangka pendek (`BearerPass`)** dari **bukti sesi jangka panjang (`StateProof`)**. Pendekatan ini memungkinkan verifikasi akses yang sangat cepat dan *stateless* sambil mempertahankan kemampuan vital untuk manajemen sesi *stateful*, termasuk pencabutan sesi instan. Dokumen ini mendefinisikan tiga profil operasional: **JTS-S (Standar)** untuk integritas penuh dengan fitur keamanan lengkap, **JTS-L (Lite)** untuk implementasi ringan dengan kompleksitas minimal, dan **JTS-C (Kerahasiaan)** untuk kerahasiaan payload total. Spesifikasi ini juga memperkenalkan terminologi klaim baru untuk menggantikan istilah lama yang kurang intuitif.

---

### **Lisensi Hak Cipta**
> Hak Cipta © 2025, ukungzulfah. Semua Hak Dilindungi.
>
> Izin dengan ini diberikan, secara gratis, kepada siapa pun yang memperoleh salinan spesifikasi ini dan dokumentasi terkait ("Perangkat Lunak"), untuk menggunakan, menyalin, memodifikasi, menggabungkan, menerbitkan, mendistribusikan, dan/atau menjual salinan Perangkat Lunak, dengan tunduk pada ketentuan berikut:
>
> Pemberitahuan hak cipta di atas dan pemberitahuan izin ini harus disertakan dalam semua salinan atau bagian substansial dari Perangkat Lunak. PERANGKAT LUNAK DISEDIAKAN "SEBAGAIMANA ADANYA", TANPA JAMINAN APA PUN, BAIK TERSURAT MAUPUN TERSIRAT.

---

### **1. Pendahuluan**

#### **1.1. Tantangan Otentikasi Modern**
Dalam arsitektur perangkat lunak modern, aplikasi dipecah menjadi layanan-layanan kecil yang independen (layanan mikro). Model ini menuntut sistem otentikasi yang ringan, terdesentralisasi, dan tidak bergantung pada sesi terpusat yang monolitik.

#### **1.2. Keterbatasan Model Token Stateless Generasi Awal**
Model otentikasi berbasis token stateless generasi pertama memberikan solusi parsial tetapi memperkenalkan kelemahan signifikan:
1.  **Kerentanan Pencabutan Sesi:** Token yang diterbitkan tidak dapat dibatalkan secara paksa dari sisi server sebelum waktu kedaluwarsanya.
2.  **Paparan Informasi:** Payload token sering kali hanya dikodekan, bukan dienkripsi, sehingga data di dalamnya dapat dibaca oleh pihak mana pun yang memegang token.
3.  **Kompleksitas Manajemen Kunci:** Penggunaan kunci simetris bersama menciptakan satu titik kegagalan berisiko tinggi di lingkungan terdistribusi.

#### **1.3. Paradigma Baru: Janus Token System (JTS)**
JTS diusulkan sebagai evolusi untuk mengatasi kelemahan-kelemahan ini. Dengan prinsip dualitasnya, JTS menggabungkan efisiensi *stateless* dengan keamanan *stateful*.

### **2. Konsep Inti JTS**

#### **2.1. Prinsip Dualitas**
JTS memisahkan peran token menjadi dua:
1.  **Akses:** Memberikan izin untuk mengakses sumber daya untuk durasi yang sangat singkat.
2.  **Sesi:** Membuktikan validitas sesi otentikasi keseluruhan pengguna.

#### **2.2. Dua Komponen JTS**
1.  **`BearerPass`:** Token akses jangka pendek yang ditandatangani secara kriptografis. Token ini digunakan di setiap permintaan API dan diverifikasi secara stateless.
2.  **`StateProof`:** Token sesi jangka panjang yang buram (opaque) dan stateful. Token ini digunakan secara eksklusif untuk mendapatkan `BearerPass` baru dan disimpan dengan aman di sisi klien. Keberadaannya di basis data server menentukan validitas sebuah sesi.

### **3. Terminologi dan Klaim JTS**

Sebagai penyempurnaan, JTS memperkenalkan terminologi klaim yang lebih eksplisit dan intuitif, beralih dari istilah-istilah lama yang ambigu.

| Klaim JTS | Nama Lengkap    | Deskripsi                                                                   | Menggantikan |
| :-------- | :-------------- | :-------------------------------------------------------------------------- | :-----------|
| **`prn`** | **Principal**   | Pengidentifikasi unik untuk prinsipal yang diautentikasi (biasanya pengguna). | `sub`       |
| **`aid`** | **Anchor ID**   | ID unik yang "mengaitkan" `BearerPass` ke catatan sesi di server.             | `sid`       |
| **`tkn_id`**| **Token ID**    | Pengidentifikasi unik untuk setiap `BearerPass`, mencegah serangan replay.  | `jti`       |
| `exp`     | Expiration Time | Waktu kedaluwarsa token (dipertahankan dari RFC 7519).                       | -           |
| `aud`     | Audience        | Penerima yang dituju untuk token ini (dipertahankan dari RFC 7519).           | -           |
| `iat`     | Issued At       | Waktu saat token diterbitkan (dipertahankan dari RFC 7519).                   | -           |

#### **3.2. Klaim Tambahan (Extended Claims)**

JTS mendefinisikan klaim tambahan untuk keamanan dan fungsionalitas yang lebih kuat:

| Klaim JTS | Nama Lengkap       | Deskripsi                                                                    | Wajib    |
| :-------- | :----------------- | :--------------------------------------------------------------------------- | :------- |
| **`dfp`** | **Device Fingerprint** | Hash dari karakteristik perangkat untuk mengikat token ke perangkat tertentu. | Tidak    |
| **`perm`**| **Permissions**    | Array string yang mendefinisikan izin/cakupan yang dimiliki token.           | Tidak    |
| **`grc`** | **Grace Period**   | Toleransi waktu (dalam detik) setelah `exp` untuk permintaan dalam proses.     | Tidak    |
| **`org`** | **Organization**   | Pengidentifikasi penyewa/organisasi untuk sistem multi-penyewa.              | Tidak    |
| **`atm`** | **Auth Method**    | Metode otentikasi yang digunakan (misalnya, `pwd`, `mfa:totp`, `sso`).        | Tidak    |
| **`ath`** | **Auth Time**      | Cap waktu Unix saat pengguna terakhir kali melakukan otentikasi aktif.         | Tidak    |
| **`spl`** | **Session Policy** | Kebijakan sesi konkuren yang berlaku (`allow_all`, `single`, `max:n`).       | Tidak    |

**Contoh Payload dengan Klaim Tambahan:**
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

### **4. Profil Standar: JTS-S (Integritas)**

Profil ini berfokus pada kecepatan, integritas, dan kemampuan pencabutan sesi.

#### **4.1. Struktur `BearerPass` (Format JWS)**
`BearerPass` dalam profil JTS-S adalah **JSON Web Signature (JWS)** yang ditandatangani dengan **kriptografi asimetris (misalnya, RS256)**.

**Contoh Header:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Catatan:** Klaim `kid` (Key ID) WAJIB untuk mendukung rotasi kunci (lihat Bagian 7).

**Contoh Payload:**
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

#### **4.2. Alur Kerja**
1.  **Otentikasi:** Pengguna login -> Server membuat catatan sesi di DB, menghasilkan `StateProof` (disimpan di DB) dan `BearerPass` (JWS). `StateProof` dikirim melalui cookie `HttpOnly`, `BearerPass` melalui badan JSON.
2.  **Akses Sumber Daya:** Klien mengirimkan `BearerPass` di header -> Server memverifikasi tanda tangan JWS menggunakan kunci publik.
3.  **Pembaruan:** `BearerPass` kedaluwarsa -> Klien memanggil endpoint `/renew` dengan `StateProof` di cookie -> Server memvalidasi `StateProof` di DB; jika valid, menerbitkan `BearerPass` baru.
4.  **Pencabutan (Logout):** Klien memanggil `/logout` -> Server menghapus catatan sesi yang terkait dengan `StateProof` dari DB. Sesi menjadi tidak valid seketika.

#### **4.3. Persyaratan Cookie dan Perlindungan CSRF**

`StateProof` yang disimpan dalam cookie HARUS memenuhi persyaratan keamanan berikut:

**Atribut Cookie WAJIB:**
```
Set-Cookie: jts_state_proof=<token>; 
  HttpOnly; 
  Secure; 
  SameSite=Strict; 
  Path=/jts; 
  Max-Age=604800
```

| Atribut     | Nilai       | Deskripsi                                                              |
| :---------- | :---------- | :--------------------------------------------------------------------- |
| `HttpOnly`  | WAJIB       | Mencegah akses dari JavaScript (mengurangi risiko XSS).                |
| `Secure`    | WAJIB       | Cookie hanya dikirim melalui HTTPS.                                    |
| `SameSite`  | `Strict`    | Mencegah pengiriman cookie pada permintaan lintas situs (mengurangi risiko CSRF). |
| `Path`      | `/jts`      | Membatasi cookie agar hanya dikirim ke endpoint JTS.                   |
| `Max-Age`   | Sesuai kebijakan | Masa pakai cookie sesuai dengan kebijakan sesi.                         |

**Perlindungan CSRF Tambahan:**

Untuk endpoint `/renew` dan `/logout`, server HARUS memvalidasi setidaknya SATU dari mekanisme berikut:

1.  **Validasi Header Origin:** Pastikan header `Origin` atau `Referer` berasal dari domain yang diizinkan.
2.  **Persyaratan Header Kustom:** Mewajibkan header kustom yang tidak dapat diatur oleh pengiriman formulir standar:
    ```
    X-JTS-Request: 1
    ```
3.  **Pola Double-Submit Cookie:** Kirim nilai token CSRF di cookie DAN di badan/header permintaan, lalu validasi bahwa keduanya cocok.

#### **4.4. Rotasi StateProof**

Untuk meningkatkan keamanan dan mendeteksi pencurian token, JTS MEWAJIBKAN rotasi `StateProof` pada setiap operasi pembaruan.

**Mekanisme:**
1.  Klien memanggil `/renew` dengan `StateProof` lama.
2.  Server memvalidasi `StateProof` lama di basis data.
3.  Jika valid:
    a.  Server MENGHAPUS atau MENANDAI `StateProof` lama sebagai *telah digunakan (consumed)*.
    b.  Server menerbitkan `StateProof` BARU dan `BearerPass` baru.
    c.  `StateProof` baru dikirim melalui header `Set-Cookie`.
4.  Jika `StateProof` lama sudah ditandai *telah digunakan* (terdeteksi replay):
    a.  Server HARUS segera mencabut SEMUA sesi yang terkait dengan `aid` tersebut.
    b.  Server HARUS mengembalikan kesalahan `JTS-401-05` (Sesi Terkompromi).
    c.  Server SEBAIKNYA mengirimkan pemberitahuan keamanan kepada pengguna.

**Diagram Rotasi:**
```
[Klien]                               [Server Otentikasi]              [Basis Data]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|                               |
    |                                       |-- Validasi StateProof_v1 ---->|
    |                                       |<-- Valid, tandai digunakan ---|
    |                                       |                               |
    |                                       |-- Hasilkan StateProof_v2 ---->|
    |                                       |<-- Tersimpan -----------------|
    |                                       |                               |
    |<-- 200 OK (BearerPass_baru) ----------|                               |
    |<-- Set-Cookie: StateProof_v2 ---------|                               |
    |                                       |                               |
```

**Deteksi Anomali (Serangan Replay):**
```
[Penyerang]                           [Server Otentikasi]              [Basis Data]
    |                                       |                               |
    |-- POST /renew (StateProof_v1) ------->|  (token curian)               |
    |                                       |-- Validasi StateProof_v1 ---->|
    |                                       |<-- TELAH DIGUNAKAN! Replay terdeteksi -|
    |                                       |                               |
    |                                       |-- CABUT semua sesi (aid) ---->|
    |                                       |<-- Selesai -------------------|
    |                                       |                               |
    |<-- 401 JTS-401-05 (Terkompromi) ------|
    |                                       |                               |
```

#### **4.5. Menangani Kondisi Balapan (Race Conditions) dalam Pembaruan Konkuren**

Dalam skenario di mana pengguna memiliki beberapa tab/jendela atau permintaan pembaruan terjadi hampir bersamaan, ada risiko deteksi replay *positif palsu*. JTS mendefinisikan mekanisme **Jendela Toleransi Rotasi (Rotation Grace Window)** untuk menangani kondisi ini.

**Masalah:**
```
[Tab A]                               [Server Otentikasi]              [Basis Data]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Tandai SP_v1 digunakan ---->|
    |                                     |                               |
[Tab B]  (sedikit tertunda)              |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Periksa SP_v1 -------------->|
    |                                     |<-- TELAH DIGUNAKAN! (positif palsu) |
    |<-- 401 JTS-401-05 ??? --------------|  (pengguna tidak terkompromi!) |
```

**Solusi: Jendela Toleransi Rotasi**

Server HARUS mengimplementasikan **jendela toleransi rotasi** dengan spesifikasi berikut:

1.  **Durasi Jendela Toleransi:** Server HARUS menyimpan `previous_state_proof` selama **5-10 detik** setelah rotasi.
2.  **Validasi Ganda:** Selama jendela toleransi, server HARUS menerima BAIK `current_state_proof` MAUPUN `previous_state_proof`.
3.  **Respons untuk Token Sebelumnya:** Jika permintaan menggunakan `previous_state_proof` yang masih dalam jendela toleransi:
    -   Server HARUS mengembalikan `StateProof` dan `BearerPass` yang SAMA yang sudah dihasilkan untuk `current_state_proof`.
    -   Server TIDAK BOLEH menghasilkan token baru (mencegah divergensi token).
4.  **Setelah Jendela Toleransi:** Permintaan dengan `previous_state_proof` yang telah melewati jendela toleransi HARUS diperlakukan sebagai serangan replay.

**Implementasi Basis Data:**
```sql
CREATE TABLE jts_sessions (
    aid                   VARCHAR(64) PRIMARY KEY,
    prn                   VARCHAR(128) NOT NULL,
    current_state_proof   VARCHAR(256) NOT NULL,
    previous_state_proof  VARCHAR(256),           -- Token sebelumnya
    rotation_timestamp    TIMESTAMP,              -- Kapan rotasi terakhir terjadi
    -- ... kolom lainnya
);
```

**Logika Validasi:**
```
function validate_state_proof(incoming_sp):
    session = db.find_by_current_sp(incoming_sp)
    if session:
        return VALID, session
    
    session = db.find_by_previous_sp(incoming_sp)
    if session:
        grace_window = 10 detik
        if now() - session.rotation_timestamp < grace_window:
            return VALID_WITHIN_GRACE, session  // Kembalikan token yang ada
        else:
            trigger_replay_detection(session.aid)
            return REPLAY_DETECTED, null
    
    return INVALID, null
```

**Diagram Pembaruan Konkuren (Ditangani):**
```
[Tab A]                               [Server Otentikasi]              [Basis Data]
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Rotasi: SP_v1 -> SP_v2 ---->|
    |                                     |   (simpan previous=SP_v1)     |
    |<-- 200 OK (BP_baru, SP_v2) ---------|                               |
    |                                     |                               |
[Tab B]  (dalam 10 detik)                |                               |
    |-- POST /renew (SP_v1) ------------->|                               |
    |                                     |-- Periksa SP_v1 -------------->|
    |                                     |<-- Ditemukan di previous_sp,  |
    |                                     |    dalam jendela toleransi ---|
    |<-- 200 OK (BP_baru, SP_v2) ---------|  (token yang sama dengan Tab A) |
    |                                     |                               |
```

> **Catatan:** Kedua tab sekarang memiliki `StateProof` yang sama (SP_v2), sehingga tetap sinkron.

#### **4.6. Periode Toleransi untuk Permintaan Dalam Proses (In-Flight)**

Untuk menangani kondisi balapan di mana `BearerPass` kedaluwarsa saat permintaan sedang dalam proses:

**Spesifikasi:**
-   Server Sumber Daya (Resource Server) DAPAT memberikan toleransi waktu (*periode toleransi*) setelah waktu `exp`.
-   Periode toleransi TIDAK BOLEH melebihi **60 detik**.
-   Jika klaim `grc` ada di payload, nilainya mendefinisikan periode toleransi dalam detik.
-   Jika klaim `grc` tidak ada, periode toleransi default adalah **0 detik** (tidak ada toleransi).

**Logika Validasi:**
```
current_time = now()
effective_expiry = token.exp + token.grc (atau 0 jika grc tidak ada)

if current_time > effective_expiry:
    return ERROR_TOKEN_EXPIRED
else:
    return VALID
```

**Catatan:** Periode toleransi TIDAK memperpanjang masa pakai token untuk tujuan audit. Waktu `exp` asli masih digunakan untuk pencatatan (logging).

### **5. Profil Ringan: JTS-L (Lite)**

Profil ini dirancang untuk kasus penggunaan dengan kompleksitas rendah yang memerlukan kemudahan implementasi tanpa mengorbankan prinsip-prinsip keamanan inti JTS.

#### **5.1. Kapan Menggunakan JTS-L**

JTS-L cocok untuk skenario berikut:

| Skenario                        | Rekomendasi         | Alasan                                               |
| :------------------------------ | :------------------ | :--------------------------------------------------- |
| MVP Startup / Prototipe         | ✅ JTS-L            | Cepat diimplementasikan, dapat ditingkatkan ke JTS-S nanti. |
| Alat Internal / Panel Admin     | ✅ JTS-L            | Basis pengguna kecil, risiko lebih rendah.             |
| Aplikasi Halaman Tunggal Sederhana| ✅ JTS-L            | Tidak perlu deteksi replay yang kompleks.            |
| API Publik dengan data sensitif | ❌ Gunakan JTS-S    | Membutuhkan perlindungan replay dan pengikatan perangkat. |
| Fintech / Kesehatan             | ❌ Gunakan JTS-S/C  | Kepatuhan dan keamanan maksimum diperlukan.          |
| SaaS Multi-penyewa              | ❌ Gunakan JTS-S    | Membutuhkan isolasi dan jejak audit lengkap.         |

#### **5.2. Perbedaan Utama dari JTS-S**

| Fitur                     | JTS-S (Standar)                  | JTS-L (Lite)                     |
| :------------------------ | :------------------------------- | :------------------------------- |
| Rotasi StateProof         | ✅ WAJIB setiap `/renew`         | ❌ OPSIONAL                      |
| Deteksi Replay            | ✅ Bawaan melalui penandaan `consumed` | ⚠️ Manual / tidak ada           |
| Sidik Jari Perangkat (`dfp`)| ✅ Direkomendasikan              | ❌ Tidak diperlukan              |
| Periode Toleransi (`grc`) | ✅ Didukung                      | ✅ Didukung                      |
| Klaim Tambahan            | ✅ Lengkap                       | ⚠️ Himpunan bagian minimal       |
| Kebijakan Sesi Konkuren   | ✅ Lengkap                       | ⚠️ Hanya `allow_all`             |
| Kompleksitas Basis Data   | Tinggi (melacak token yang digunakan) | Rendah (tabel sesi sederhana)    |
| Kode Kesalahan            | Lengkap (semua kode)             | Himpunan bagian esensial         |

#### **5.3. Struktur `BearerPass` JTS-L**

`BearerPass` di JTS-L masih menggunakan **JWS dengan kriptografi asimetris**, tetapi dengan payload yang lebih minimalis.

**Header:**
```json
{
  "alg": "RS256",
  "typ": "JTS-L/v1",
  "kid": "auth-server-key-2025-001"
}
```

**Payload Minimal:**
```json
{
  "prn": "user-12345",
  "aid": "session-anchor-abcdef",
  "exp": 1764515700,
  "iat": 1764515400
}
```

**Catatan:** Klaim `tkn_id` bersifat **OPSIONAL** di JTS-L karena deteksi replay tidak diwajibkan.

#### **5.4. Alur Kerja JTS-L (Disederhanakan)**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ALUR SEDERHANA JTS-L                                  │
└─────────────────────────────────────────────────────────────────────────────┘

[Klien]                               [Server Otentikasi]              [Basis Data]
    │                                       |                               |
    │── POST /login (kredensial) ──────────>│                               |
    │                                       │── Buat Sesi ─────────────>│
    │                                       │<── ID Sesi ───────────────────│
    │<── 200 OK ────────────────────────────│                               |
    │    BearerPass (badan)                 │                               |
    │    StateProof (cookie)                │                               |
    │                                       │                               |
    │   ... BearerPass kedaluwarsa ...      │                               |
    │                                       │                               |
    │── POST /renew (StateProof) ──────────>│                               |
    │                                       │── Periksa Sesi Ada ────────>│
    │                                       │<── Valid ─────────────────────│
    │                                       │   (TANPA rotasi, TANPA `consumed`)  │
    │<── 200 OK ────────────────────────────│                               |
    │    BearerPass_baru (badan)            │                               |
    │    (StateProof tidak berubah)         │                               |
    │                                       │                               |
```

**Perbedaan Utama:**
-   `StateProof` **TIDAK dirotasi** pada setiap `/renew`—token yang sama dapat digunakan berkali-kali selama sesi aktif.
-   Server hanya perlu memeriksa apakah catatan sesi **ada** di basis data, tanpa perlu melacak status "telah digunakan".
-   Kompleksitas basis data berkurang secara signifikan.

#### **5.5. Skema Basis Data JTS-L**

Basis data untuk JTS-L jauh lebih sederhana:

```sql
-- JTS-L: Tabel Sesi Sederhana
CREATE TABLE jts_sessions (
    aid             VARCHAR(64) PRIMARY KEY,  -- Anchor ID (StateProof)
    prn             VARCHAR(128) NOT NULL,    -- Principal (ID Pengguna)
    created_at      TIMESTAMP DEFAULT NOW(),
    expires_at      TIMESTAMP NOT NULL,
    last_active     TIMESTAMP DEFAULT NOW(),
    user_agent      TEXT,                     -- Opsional: untuk daftar sesi
    ip_address      VARCHAR(45)               -- Opsional: untuk audit
);

-- Indeks untuk kueri berdasarkan pengguna
CREATE INDEX idx_sessions_prn ON jts_sessions(prn);
```

**Bandingkan dengan JTS-S yang memerlukan:**
```sql
-- JTS-S: Tabel Sesi Lengkap dengan Pelacakan Rotasi
CREATE TABLE jts_sessions (
    aid                  VARCHAR(64) PRIMARY KEY,
    prn                  VARCHAR(128) NOT NULL,
    current_state_proof  VARCHAR(256) NOT NULL,
    previous_state_proof VARCHAR(256),        -- Untuk jendela toleransi
    state_proof_version  INTEGER DEFAULT 1,
    consumed_at          TIMESTAMP,             -- Deteksi replay
    device_fingerprint   VARCHAR(128),
    created_at           TIMESTAMP DEFAULT NOW(),
    expires_at           TIMESTAMP NOT NULL,
    last_active          TIMESTAMP DEFAULT NOW(),
    -- ... kolom lainnya
);

-- Tabel tambahan untuk melacak token yang telah digunakan
CREATE TABLE jts_consumed_tokens (
    tkn_id          VARCHAR(64) PRIMARY KEY,
    aid             VARCHAR(64) REFERENCES jts_sessions(aid),
    consumed_at     TIMESTAMP DEFAULT NOW()
);
```

#### **5.6. Himpunan Bagian Kode Kesalahan untuk JTS-L**

JTS-L hanya WAJIB mengimplementasikan himpunan bagian kode kesalahan berikut:

| Kode Kesalahan | Kunci Kesalahan      | Deskripsi                                   |
| :------------- | :------------------- | :------------------------------------------ |
| `JTS-400-01`   | `malformed_token`    | Token tidak dapat di-parse.                 |
| `JTS-401-01`   | `bearer_expired`     | BearerPass telah kedaluwarsa.               |
| `JTS-401-02`   | `signature_invalid`  | Tanda tangan tidak valid.                   |
| `JTS-401-03`   | `stateproof_invalid` | StateProof tidak valid.                     |
| `JTS-401-04`   | `session_terminated` | Sesi telah dihentikan.                      |

**Kode kesalahan berikut TIDAK diwajibkan di JTS-L:**
-   `JTS-401-05` (session_compromised) — tidak ada deteksi replay
-   `JTS-401-06` (device_mismatch) — tidak ada pengikatan perangkat
-   `JTS-403-03` (org_mismatch) — tidak ada dukungan multi-penyewa

#### **5.7. Migrasi dari JTS-L ke JTS-S**

JTS-L dirancang agar mudah ditingkatkan ke JTS-S seiring meningkatnya kebutuhan keamanan:

**Langkah-langkah Migrasi:**

1.  **Perbarui Tipe Header:**
    ```json
    // Sebelum
    { "typ": "JTS-L/v1" }
    // Sesudah
    { "typ": "JTS-S/v1" }
    ```

2.  **Tambahkan Kolom Basis Data:**
    ```sql
    ALTER TABLE jts_sessions 
    ADD COLUMN current_state_proof VARCHAR(256),
    ADD COLUMN state_proof_version INTEGER DEFAULT 1,
    ADD COLUMN consumed_at TIMESTAMP,
    ADD COLUMN device_fingerprint VARCHAR(128);
    ```

3.  **Implementasikan Rotasi StateProof:** Perbarui logika `/renew` untuk menghasilkan StateProof baru.

4.  **Tambahkan `tkn_id` ke Payload:** Mulai hasilkan ID token unik untuk setiap BearerPass.

5.  **Peluncuran Bertahap:**
    -   Fase 1: Server menerima token JTS-L dan JTS-S
    -   Fase 2: Semua token baru adalah JTS-S
    -   Fase 3: Tolak token JTS-L setelah masa pakai sesi maksimum

#### **5.8. Keterbatasan dan Risiko JTS-L**

> ⚠️ **PERINGATAN:** Pelaksana HARUS memahami risiko-risiko berikut sebelum memilih JTS-L:

| Risiko                      | Dampak                                                        | Mitigasi                               |
| :-------------------------- | :------------------------------------------------------------ | :--------------------------------------- |
| **Tidak ada deteksi replay**| `StateProof` yang dicuri dapat digunakan berkali-kali tanpa terdeteksi. | Gunakan `exp` yang lebih pendek untuk sesi. |
| **Tidak ada pengikatan perangkat**| Token dapat digunakan dari perangkat yang berbeda.            | Terapkan pembatasan laju berbasis IP.      |
| **Pencurian tidak terdeteksi**| Pengguna tidak akan diberi tahu jika token mereka dicuri.      | Pantau pola login, beri tahu pada IP baru. |

**Rekomendasi Mitigasi untuk JTS-L:**
-   Atur kedaluwarsa `StateProof` lebih singkat (maks 24 jam vs. 7 hari di JTS-S)
-   Terapkan pembatasan laju (rate limiting) pada endpoint `/renew`
-   Catat semua aktivitas pembaruan untuk audit manual
-   Pertimbangkan notifikasi email untuk login dari IP/lokasi baru

---

### **6. Profil Kerahasiaan: JTS-C (Confidentiality)**

Profil ini menambahkan lapisan enkripsi untuk kerahasiaan payload total.

#### **6.1. Struktur `BearerPass` (Format JWE)**
`BearerPass` dalam profil JTS-C adalah **JSON Web Encryption (JWE)**. Token JWS dari profil standar "dibungkus" atau dienkripsi menjadi JWE.

#### **6.2. Alur Kerja**
*   **Pembuatan Token ("Ditandatangani-lalu-Dienkripsi"):**
    1.  Buat JWS seperti pada profil JTS-S.
    2.  Enkripsi seluruh JWS menggunakan **kunci publik dari Server Sumber Daya yang dituju**. Hasilnya adalah JWE.
*   **Verifikasi Token ("Didekripsi-lalu-Diverifikasi"):**
    1.  Server Sumber Daya menerima JWE.
    2.  Server mendekripsi JWE menggunakan **kunci privatnya sendiri**. Hasilnya adalah JWS asli.
    3.  Server memverifikasi JWS menggunakan **kunci publik dari Server Otentikasi**.

### **7. Analisis Keamanan dan Penanganan Kesalahan**

#### **7.1. Analisis Keamanan**

*   **Pencabutan Sesi:** Terselesaikan sepenuhnya melalui manajemen `StateProof` di basis data server.
*   **Kebocoran Kredensial:** Diminimalkan dengan penggunaan wajib kriptografi asimetris dan pengamanan `StateProof` dalam cookie `HttpOnly`.
*   **Kebocoran Informasi:** Diminimalkan di JTS-S/JTS-L dengan payload minimalis dan diselesaikan sepenuhnya di JTS-C melalui enkripsi JWE.
*   **Serangan Replay:** Dimitigasi dengan `tkn_id` unik dan **rotasi StateProof** di JTS-S. **Catatan:** JTS-L tidak menyediakan perlindungan replay otomatis.
*   **Serangan XSS:** Risiko pencurian token sesi `StateProof` berkurang secara signifikan karena flag `HttpOnly` pada cookie.
*   **Serangan CSRF:** Dimitigasi dengan kombinasi `SameSite=Strict` dan validasi header tambahan.
*   **Pencurian Token:** Dimitigasi dengan **Sidik Jari Perangkat (`dfp`)** di JTS-S. **Catatan:** JTS-L tidak mendukung pengikatan perangkat.

#### **7.2. Kode Kesalahan Standar**

JTS mendefinisikan kode kesalahan standar untuk konsistensi implementasi dan kemudahan debugging:

**Format Respons Kesalahan:**
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

**Daftar Kode Kesalahan:**

| Kode Kesalahan | Status HTTP | Kunci Kesalahan        | Deskripsi                                              | Aksi     |
| :------------- | :---------- | :--------------------- | :----------------------------------------------------- | :------- |
| `JTS-400-01`   | 400         | `malformed_token`      | Token tidak dapat di-parse atau formatnya tidak valid. | `reauth` |
| `JTS-400-02`   | 400         | `missing_claims`       | Klaim yang diperlukan hilang dari token.               | `reauth` |
| `JTS-401-01`   | 401         | `bearer_expired`       | BearerPass telah kedaluwarsa.                          | `renew`  |
| `JTS-401-02`   | 401         | `signature_invalid`    | Tanda tangan BearerPass tidak valid.                   | `reauth` |
| `JTS-401-03`   | 401         | `stateproof_invalid`   | StateProof tidak valid atau tidak ditemukan di DB.     | `reauth` |
| `JTS-401-04`   | 401         | `session_terminated`   | Sesi dihentikan (logout atau kebijakan konkuren).      | `reauth` |
| `JTS-401-05`   | 401         | `session_compromised`  | Serangan replay terdeteksi; semua sesi dicabut.        | `reauth` |
| `JTS-401-06`   | 401         | `device_mismatch`      | Sidik jari perangkat tidak cocok.                      | `reauth` |
| `JTS-403-01`   | 403         | `audience_mismatch`    | Token tidak ditujukan untuk sumber daya ini.           | `none`   |
| `JTS-403-02`   | 403         | `permission_denied`    | Token tidak memiliki izin yang diperlukan.             | `none`   |
| `JTS-403-03`   | 403         | `org_mismatch`         | Token milik organisasi/penyewa yang berbeda.           | `none`   |
| `JTS-500-01`   | 500         | `key_unavailable`      | Kunci publik untuk verifikasi tidak tersedia.          | `retry`  |

**Nilai Aksi:**
-   `renew`: Klien harus memanggil endpoint `/renew` untuk mendapatkan BearerPass baru.
-   `reauth`: Pengguna harus melakukan otentikasi ulang (login).
-   `retry`: Permintaan dapat dicoba lagi setelah `retry_after` detik.
-   `none`: Tidak ada tindakan yang dapat memperbaiki kondisi ini.

### **8. Manajemen Kunci**

#### **8.1. Persyaratan Key ID**

Setiap `BearerPass` HARUS menyertakan klaim `kid` (Key ID) di header untuk mengidentifikasi kunci yang digunakan untuk menandatangani.

**Format Header dengan kid:**
```json
{
  "alg": "RS256",
  "typ": "JTS-S/v1",
  "kid": "auth-server-key-2025-001"
}
```

#### **8.2. Prosedur Rotasi Kunci**

Untuk mengganti kunci penandatanganan tanpa membatalkan token yang sudah diterbitkan:

**Langkah-langkah:**
1.  **Hasilkan Pasangan Kunci Baru:** Buat pasangan kunci baru dengan `kid` yang unik.
2.  **Publikasikan Kunci Publik:** Tambahkan kunci publik baru ke endpoint JWKS. Server HARUS mendukung beberapa kunci publik aktif.
3.  **Mulai Menandatangani dengan Kunci Baru:** Semua token `BearerPass` baru ditandatangani dengan kunci baru.
4.  **Pensiunkan Kunci Lama:** Setelah `max_bearer_lifetime` + buffer (rekomendasi: 15 menit), hapus kunci publik lama dari JWKS.

**Respons Endpoint JWKS:**
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

**Catatan:** Bidang `exp` dalam entri kunci menunjukkan kapan kunci akan dipensiunkan (opsional, untuk informasi klien).

#### **8.3. Endpoint JWKS Standar**

JTS mendefinisikan jalur standar untuk endpoint JWKS (JSON Web Key Set) sehingga Server Sumber Daya dapat secara konsisten menemukan kunci publik.

**Jalur Standar:**
```
GET /.well-known/jts-jwks
```

**Persyaratan:**

| Aspek            | Spesifikasi                                           |
| :--------------- | :---------------------------------------------------- |
| **Jalur**        | `/.well-known/jts-jwks` (WAJIB)                       |
| **Metode**       | `GET`                                                 |
| **Otentikasi**   | Tidak diperlukan (endpoint publik)                    |
| **Content-Type** | `application/json`                                    |
| **CORS**         | HARUS mengizinkan permintaan lintas-asal dari domain yang valid |

**Caching:**

Server HARUS menyertakan header caching yang sesuai:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600, stale-while-revalidate=60
ETag: "jwks-v2-abc123"
```

| Header                   | Nilai yang Direkomendasikan | Deskripsi                                                 |
| :----------------------- | :--------------------- | :-------------------------------------------------------- |
| `Cache-Control`          | `max-age=3600`         | Cache selama 1 jam.                                       |
| `stale-while-revalidate` | `60`                   | Izinkan respons usang selama 60 detik saat revalidasi.      |
| `ETag`                   | Hash dari konten JWKS  | Untuk permintaan bersyarat.                               |

**Penemuan (Opsional):**

Untuk mendukung penemuan otomatis, Server Otentikasi DAPAT menyediakan endpoint metadata:

```
GET /.well-known/jts-configuration
```

**Respons:**
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

#### **8.4. Algoritma yang Didukung**

JTS merekomendasikan algoritma berikut:

| Algoritma | Tipe       | Rekomendasi          | Catatan                                    |
| :-------- | :--------- | :------------------- | :----------------------------------------- |
| `RS256`   | Asimetris  | DIREKOMENDASIKAN     | RSA dengan SHA-256, didukung secara luas.  |
| `RS384`   | Asimetris  | DIDUKUNG             | RSA dengan SHA-384.                        |
| `RS512`   | Asimetris  | DIDUKUNG             | RSA dengan SHA-512.                        |
| `ES256`   | Asimetris  | DIREKOMENDASIKAN     | ECDSA dengan P-256, lebih efisien.         |
| `ES384`   | Asimetris  | DIDUKUNG             | ECDSA dengan P-384.                        |
| `ES512`   | Asimetris  | DIDUKUNG             | ECDSA dengan P-521.                        |
| `PS256`   | Asimetris  | DIDUKUNG             | RSASSA-PSS dengan SHA-256.                 |
| `HS256`   | Simetris   | **TIDAK DIIZINKAN**  | Tidak sejalan dengan prinsip JTS.          |
| `HS384`   | Simetris   | **TIDAK DIIZINKAN**  | Tidak sejalan dengan prinsip JTS.          |
| `HS512`   | Simetris   | **TIDAK DIIZINKAN**  | Tidak sejalan dengan prinsip JTS.          |
| `none`    | -          | **DILARANG**         | Tanpa tanda tangan, sangat tidak aman.     |

### **9. Kebijakan Sesi Konkuren**

JTS mendefinisikan kebijakan untuk menangani situasi di mana satu pengguna memiliki beberapa sesi aktif.

> **Catatan:** Kebijakan sesi konkuren hanya berlaku untuk **JTS-S** dan **JTS-C**. Profil **JTS-L** hanya mendukung kebijakan `allow_all` secara default.

#### **9.1. Pilihan Kebijakan**

| Kebijakan       | Klaim `spl` | Perilaku                                                    |
| :-------------- | :---------- | :-------------------------------------------------------- |
| **Izinkan Semua**| `allow_all` | Semua sesi valid secara bersamaan tanpa batas.            |
| **Tunggal**     | `single`    | Hanya satu sesi aktif. Login baru membatalkan yang lama.    |
| **Maks N**      | `max:3`     | Maksimum N sesi aktif. Yang tertua akan dikeluarkan jika terlampaui. |
| **Beri Tahu**   | `notify`    | Semua sesi valid, tetapi pengguna diberi tahu tentang yang lain. |

#### **9.2. Implementasi**

Ketika seorang pengguna login dan kebijakan membatasi jumlah sesi:
```
1. Pengguna login -> Server memeriksa jumlah sesi aktif untuk `prn` ini
2. Jika jumlah >= batas:
   a. Kebijakan "single": Cabut semua sesi lama, buat yang baru
   b. Kebijakan "max:n": Cabut sesi tertua (FIFO), buat yang baru
3. Buat catatan sesi baru di DB
4. Kembalikan StateProof dan BearerPass
```

#### **9.3. Notifikasi Sesi**

Untuk kebijakan `notify`, server SEBAIKNYA menyediakan endpoint untuk melihat sesi aktif:

```
GET /jts/sessions
Authorization: Bearer <BearerPass>

Respons:
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

### **10. Dukungan Multi-Platform**

#### **10.1. Platform Web (Default)**

Untuk aplikasi web, `StateProof` disimpan dalam cookie `HttpOnly` sesuai Bagian 4.3.

#### **10.2. Platform Seluler/Natif**

Untuk aplikasi seluler dan desktop natif di mana cookie tidak praktis:

**Penyimpanan:**
-   **iOS:** Keychain Services dengan `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
-   **Android:** EncryptedSharedPreferences atau Keystore System
-   **Desktop:** OS Credential Manager (Windows Credential Vault, macOS Keychain)

**Pengiriman StateProof:**
```
POST /jts/renew
X-JTS-StateProof: <encrypted_state_proof>
Content-Type: application/json
```

**Persyaratan Tambahan untuk Non-Cookie:**
-   `StateProof` HARUS dienkripsi saat disimpan di klien.
-   Permintaan dengan header `X-JTS-StateProof` HARUS menyertakan `X-JTS-Device-ID` untuk validasi.
-   Server HARUS memvalidasi bahwa `Device-ID` cocok dengan yang terdaftar selama otentikasi awal.

#### **10.3. Server-ke-Server (M2M)**

Untuk komunikasi mesin-ke-mesin:

-   `StateProof` TIDAK digunakan (tidak ada konsep "sesi pengguna").
-   `BearerPass` diterbitkan dengan `exp` yang lebih lama (rekomendasi: 1 jam).
-   Klaim `prn` berisi pengidentifikasi layanan/mesin, bukan pengguna.
-   Klaim `atm` diatur ke `client_credentials`.

**Contoh Payload M2M:**
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

### **11. Kesimpulan**

Janus Token System (JTS) menawarkan kerangka kerja otentikasi yang seimbang, menggabungkan kinerja tinggi verifikasi stateless dengan kontrol keamanan ketat dari manajemen sesi stateful. Dengan arsitektur dua komponen, terminologi yang jelas, dan profil operasional yang fleksibel, JTS dirancang untuk menjadi standar otentikasi yang kuat dan aman untuk aplikasi generasi berikutnya.

**Tiga Profil untuk Berbagai Kebutuhan:**

| Profil                    | Kasus Penggunaan                   | Kompleksitas | Keamanan      |
| :------------------------ | :--------------------------------- | :-----------| :------------ |
| **JTS-L (Lite)**          | MVP, Alat Internal, Aplikasi Sederhana | ⭐ Rendah   | ⭐⭐ Dasar    |
| **JTS-S (Standar)**       | Aplikasi Produksi, API Publik      | ⭐⭐ Sedang  | ⭐⭐⭐⭐ Tinggi   |
| **JTS-C (Kerahasiaan)**   | Fintech, Kesehatan, Keamanan Tinggi| ⭐⭐⭐ Tinggi | ⭐⭐⭐⭐⭐ Maksimum |

**Keunggulan JTS dibandingkan sistem token generasi sebelumnya:**
1.  **Pencabutan Instan:** Melalui manajemen `StateProof` dan rotasi token (JTS-S/C).
2.  **Deteksi Pencurian Token:** Melalui mekanisme rotasi yang mendeteksi replay (JTS-S/C).
3.  **Perlindungan Berlapis:** Perlindungan CSRF, pengikatan perangkat, dan enkripsi opsional.
4.  **Standardisasi Kesalahan:** Kode kesalahan yang konsisten untuk debugging dan penanganan.
5.  **Fleksibilitas Platform:** Dukungan untuk web, seluler, dan server-ke-server.
6.  **Manajemen Kunci:** Prosedur rotasi kunci yang jelas tanpa waktu henti.
7.  **Peningkatan Progresif:** Jalur migrasi yang jelas dari JTS-L → JTS-S → JTS-C seiring pertumbuhan aplikasi.

---

### **Lampiran A: Daftar Periksa Implementasi**

Pelaksana HARUS memenuhi daftar periksa berikut untuk kepatuhan JTS:

#### **Daftar Periksa JTS-L (Lite):**

**Wajib (HARUS):**
- [ ] Gunakan kriptografi asimetris (RS256, ES256, dll.)
- [ ] Sertakan `kid` di header setiap BearerPass
- [ ] Simpan StateProof di cookie HttpOnly dengan SameSite=Strict
- [ ] Validasi CSRF pada endpoint `/renew` dan `/logout`
- [ ] Kembalikan respons kesalahan sesuai format standar (himpunan bagian)

**Direkomendasikan (SEBAIKNYA):**
- [ ] Atur kedaluwarsa StateProof maksimal 24 jam
- [ ] Terapkan pembatasan laju pada `/renew`
- [ ] Catat semua aktivitas pembaruan

---

#### **Daftar Periksa JTS-S (Standar):**

**Wajib (HARUS):**
- [ ] Gunakan kriptografi asimetris (RS256, ES256, dll.)
- [ ] Sertakan `kid` di header setiap BearerPass
- [ ] Simpan StateProof di cookie HttpOnly dengan SameSite=Strict
- [ ] Terapkan rotasi StateProof pada setiap `/renew`
- [ ] Deteksi replay dan cabut sesi saat terdeteksi
- [ ] Validasi CSRF pada endpoint `/renew` dan `/logout`
- [ ] Kembalikan respons kesalahan sesuai format standar (lengkap)

**Direkomendasikan (SEBAIKNYA):**
- [ ] Terapkan sidik jari perangkat (`dfp`)
- [ ] Dukung periode toleransi untuk permintaan dalam proses
- [ ] Sediakan endpoint `/sessions` untuk visibilitas
- [ ] Terapkan kebijakan sesi konkuren
- [ ] Kirim pemberitahuan keamanan saat anomali terdeteksi

**Opsional (DAPAT):**
- [ ] Terapkan endpoint introspeksi
- [ ] Dukung multi-penyewaan dengan klaim `org`

---

#### **Daftar Periksa JTS-C (Kerahasiaan):**

**Wajib (HARUS):**
- [ ] Semua persyaratan JTS-S
- [ ] Terapkan enkripsi JWE (ditandatangani-lalu-dienkripsi)
- [ ] Kelola kunci enkripsi secara terpisah dari kunci penandatanganan

**Opsional (DAPAT):**
- [ ] Dukung beberapa kunci enkripsi Server Sumber Daya
- [ ] Terapkan protokol pertukaran kunci untuk kunci enkripsi

---

### **Lampiran B: Contoh Alur Lengkap**

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ALUR OTENTIKASI JTS                                   │
└─────────────────────────────────────────────────────────────────────────────┘

[Pengguna]      [Aplikasi Klien]     [Server Otentikasi]  [Server Sumber Daya]
   │                 │                     │                      │
   │─── Login ──────>│                     │                      │
   │                 │─── POST /login ────>│                      │
   │                 │    (kredensial)     │                      │
   │                 │                     │── Buat Sesi ────────>│ [DB]
   │                 │                     │<─ Catatan Sesi ──────│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass (badan)│                     │
   │                 │    StateProof (cookie)                     │
   │                 │                     │                      │
   │                 │─────────── GET /api/resource ─────────────>│
   │                 │            Authorization: Bearer <BP>      │
   │                 │                     │                      │
   │                 │                     │    Verifikasi tanda tangan │
   │                 │                     │    (stateless)       │
   │                 │<────────── 200 OK ─────────────────────────│
   │<── Data ───────│                     │                      │
   │                 │                     │                      │
   │    ... BearerPass kedaluwarsa ...    │                      │
   │                 │                     │                      │
   │                 │─── POST /renew ────>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Validasi SP_v1 ───>│ [DB]
   │                 │                     │<─ Valid, digunakan ──│
   │                 │                     │── Simpan SP_v2 ─────>│
   │                 │                     │                      │
   │                 │<── 200 OK ─────────│                      │
   │                 │    BearerPass_baru  │                      │
   │                 │    StateProof_v2 (cookie)                  │
   │                 │                     │                      │
   │─── Logout ─────>│                     │                      │
   │                 │─── POST /logout ───>│                      │
   │                 │    (cookie StateProof)                     │
   │                 │                     │── Hapus Sesi ───────>│ [DB]
   │                 │<── 200 OK ─────────│                      │
   │<── Logout berhasil ─│                     │                      │
   │                 │                     │                      │
```

---

### **Lampiran C: Referensi**

-   RFC 7519 - JSON Web Token (JWT)
-   RFC 7515 - JSON Web Signature (JWS)
-   RFC 7516 - JSON Web Encryption (JWE)
-   RFC 7517 - JSON Web Key (JWK)
-   RFC 6749 - The OAuth 2.0 Authorization Framework
-   OWASP Session Management Cheat Sheet
-   OWASP Cross-Site Request Forgery Prevention Cheat Sheet
