# Analisis Kerentanan — Robot (VulNyx)

Breakdown alur exploitation mesin "Robot" (VulNyx) berdasarkan tiap tahap, beserta kerentanan/kelemahan (CWE) yang mendasarinya.

---

## 1. Information Disclosure via Image Metadata (Steganography/EXIF)

**Apa yang terjadi:** File `image.jpg` di halaman utama menyimpan path tersembunyi (`/B4ckUp_3LLi0t`) di field `Comment` metadata EXIF-nya.

**Kelemahan yang mendasari:**
- **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor** — developer menaruh informasi sensitif (path direktori rahasia) di metadata file yang publicly accessible, dengan asumsi "security by obscurity" (nggak ada yang bakal cek metadata gambar).
- Bukan vuln teknis yang "exploitable" secara langsung, tapi klasik **information leakage** yang jadi entry point buat reconnaissance lanjutan. Di dunia nyata, ini sering terjadi lewat metadata dokumen (Word/PDF) yang bocorin username, software version, internal path, dll.

**Pelajaran:** Selalu strip metadata sebelum publish file (pakai `exiftool -all= file.jpg`), dan jangan pernah andalkan "hidden path" sebagai kontrol akses.

---

## 2. Directory/Backup File Exposure

**Apa yang terjadi:** Gobuster fuzzing di `/B4ckUp_3LLi0t/` nemuin `connect.bak` — backup file dari source code PHP yang isinya kredensial MongoDB plaintext.

**Kelemahan yang mendasari:**
- **CWE-530: Exposure of Backup File to an Unauthorized Control Sphere** — file backup (`.bak`) ditinggal di web root yang accessible publik. Web server (Apache) nggak di-block akses ke file dengan ekstensi `.bak`.
- **CWE-798: Use of Hard-coded Credentials** — kredensial MongoDB (`mongo:m0ng0P4zz`) di-hardcode langsung di source code, bukan di environment variable atau secret manager.
- **CWE-312: Cleartext Storage of Sensitive Information** — password disimpan plaintext di file config.

**Root cause umum:** developer edit file di production, editor bikin backup otomatis (`.bak`, `~`, `.swp`), lupa dihapus. Ini kenapa fuzzing dengan wordlist + common extensions (`-x bak,zip,rar,old,txt`) selalu worth dicoba di setiap engagement.

---

## 3. MongoDB — Authenticated tapi Credential-nya Bocor

**Apa yang terjadi:** MongoDB sebenarnya udah require auth (`command listDatabases requires authentication`), tapi karena credential-nya bocor dari step sebelumnya, attacker bisa connect dan baca data personal Elliot (nama, nickname, tanggal lahir).

**Catatan penting:** MongoDB di sini sebenarnya **dikonfigurasi dengan benar** (authentication enabled) — vuln-nya bukan di MongoDB-nya, tapi credential leakage di step 2. Ini contoh bagus kenapa **defense in depth** penting: satu kontrol yang benar (auth) bisa dilewatin kalau kontrol lain (secret management) gagal.

---

## 4. Weak Password via OSINT-based Wordlist (CUPP)

**Apa yang terjadi:** Data personal (nama, nickname, tanggal lahir) dipakai buat generate wordlist custom dengan `cupp`, lalu brute-force SSH pakai `hydra` berhasil nemuin password `toillE71986`.

**Kelemahan yang mendasari:**
- **CWE-521: Weak Password Requirements** — password user `elliot` predictable karena berbasis data personal (nickname + tahun lahir).
- **CWE-307: Improper Restriction of Excessive Authentication Attempts** — SSH server nggak ada rate limiting/lockout (fail2ban dsb) sehingga brute force dengan ribuan attempt bisa jalan tanpa hambatan.

**Kenapa ini penting di real world:** ini nunjukin kenapa **password policy** harus melarang password berbasis PII (nama, tanggal lahir, dll), dan kenapa OSINT recon (termasuk data yang bocor dari breach sebelumnya) jadi bagian penting attack chain.

---

## 5. Privilege Escalation Chain via Sudo Misconfiguration

Bagian paling menarik — rantai **lateral/vertical privilege escalation** murni lewat sudo misconfig, user demi user:

| Step | User asal | Binary sudo | User tujuan |
|---|---|---|---|
| 1 | elliot | `/usr/bin/sh` | darlene |
| 2 | darlene | `/usr/bin/python3` | angela |
| 3 | angela | `/usr/bin/awk` | tyrell |
| 4 | tyrell | `/usr/bin/zzuf` | root |

**Kelemahan yang mendasari (sama di semua step):**
- **CWE-269: Improper Privilege Management** — admin kasih izin `NOPASSWD` untuk menjalankan binary-binary "GTFOBins-able" (binary yang dikenal bisa spawn shell atau baca/tulis file arbitrary) sebagai user lain.
- **CWE-250: Execution with Unnecessary Privileges** — binary seperti `sh`, `python3`, `awk`, `zzuf` itu **general-purpose interpreters/tools**, bukan aplikasi spesifik dengan scope terbatas. Kalau kamu kasih sudo access ke ini, kamu secara efektif kasih **full shell access** sebagai target user, karena semuanya punya cara buat spawn shell:

```bash
# sh -> langsung shell
sudo -u darlene /usr/bin/sh

# python3 -> spawn shell lewat os.system
sudo -u angela /usr/bin/python3 -c 'import os; os.system("/bin/bash")'

# awk -> shell escape (GTFOBins classic)
sudo -u tyrell /usr/bin/awk 'BEGIN {system("/bin/sh")}'

# zzuf -> -c flag execute command as wrapper, bisa dipakai buat chmod SUID bash
sudo -u root /usr/bin/zzuf -c chmod 4755 /bin/bash
```

**Root cause-nya kenapa ini terjadi di real world:** biasanya karena admin butuh satu user bisa run *satu task spesifik* (misal python script tertentu), tapi sudoers rule-nya ditulis terlalu longgar — kasih akses ke seluruh binary interpreter, bukan ke script/command spesifik dengan argumen yang di-lock.

**Mitigasi yang benar:**
- Sudoers rule harus spesifik ke command + argument lengkap, bukan cuma binary path: `(darlene) NOPASSWD: /usr/bin/python3 /opt/scripts/task.py`
- Cek referensi [GTFOBins](https://gtfobins.github.io/) sebelum kasih sudo access ke binary apapun — hampir semua interpreter/compiler/text-editor/network-tool punya "escape hatch".
- Final step (`zzuf`) khususnya berbahaya karena punya flag `-c` yang literally designed buat execute arbitrary command sebagai wrapper — begitu bisa run sebagai root, SUID bash = root shell permanen.

---

## Ringkasan Attack Chain (Kill Chain View)

```
Info Disclosure (EXIF metadata)
       ↓
Backup File Exposure (.bak di web root)
       ↓
Hardcoded Credentials (MongoDB)
       ↓
PII Leakage (MongoDB data) → OSINT wordlist
       ↓
Weak Password + No Rate Limiting → SSH access (elliot)
       ↓
Sudo Misconfig Chain: elliot → darlene → angela → tyrell → root
```

Yang menarik dari box ini: **nggak ada satupun CVE (vulnerability di software tertentu)** yang dipakai — semuanya murni **CWE / misconfiguration class**: information disclosure, hardcoded credentials, weak password policy, dan improper privilege management. Ini realistis banget karena di dunia nyata, breach jauh lebih sering terjadi karena **kesalahan konfigurasi manusia** dibanding zero-day exploit.
