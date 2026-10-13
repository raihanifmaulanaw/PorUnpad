# PorUnpad v5 — VS Code

## Menjalankan
1. Instal Node.js 20+.
2. Ekstrak ZIP lalu buka folder ini di VS Code.
3. Terminal → New Terminal, jalankan `npm install`, lalu `npm start`.
4. Buka http://localhost:3000.

## Login lokal
Gunakan email berakhiran `@mail.unpad.ac.id`. Klik kirim kode; OTP akan dicetak di terminal tempat server berjalan. Ini simulasi lokal, bukan email sungguhan.

## Fitur
- Laporan fasilitas + foto JPG/PNG/WebP maksimal 5 MB.
- Forum barang hilang/ditemukan + foto.
- Profil NPM, username, dan prodi bebas.
- SQLite di `data/porunpad.db`, foto di `public/uploads/`.

Data dari situs Hatchable tidak disalin otomatis. Ini paket development lokal. Sebelum production, gunakan layanan OTP/email sungguhan, HTTPS, dan session secret yang aman.
