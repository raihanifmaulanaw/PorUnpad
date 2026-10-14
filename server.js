const express = require("express"),
  session = require("express-session"),
  multer = require("multer"),
  path = require("path"),
  crypto = require("crypto"),
  { Pool } = require("pg");

// === Konfigurasi PostgreSQL ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Inisialisasi Tabel PostgreSQL
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS profiles(
      user_id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      npm TEXT UNIQUE,
      prodi TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS reports(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      reporter_name TEXT NOT NULL,
      prodi TEXT NOT NULL,
      category TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      location TEXT NOT NULL,
      image_url TEXT,
      status TEXT DEFAULT 'Menunggu',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS lost_items(
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      username TEXT NOT NULL,
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      location TEXT NOT NULL,
      contact TEXT NOT NULL,
      image_url TEXT,
      status TEXT DEFAULT 'Aktif',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}
initDB().catch(err => console.error("Gagal membuat tabel database:", err));

// === Integrasi Cloudinary ===
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'porunpad_uploads',
    allowed_formats: ['jpg', 'png', 'webp'],
  },
});

const app = express(),
  PORT = process.env.PORT || 3000,
  ROOT = __dirname;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "local-only-change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 28800000 },
  })
);
app.use(express.static(path.join(ROOT, "public")));

const emailOK = (e) => /^[^\s@]+@mail\.unpad\.ac\.id$/i.test(String(e || "")),
      clean = (v, n = 2500) => String(v ?? "").trim().slice(0, n),
      user = (req) => req.session.user;

function auth(req, res, next) {
  if (!user(req))
    return res.status(401).json({ error: "Silakan masuk terlebih dahulu." });
  next();
}

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    cb(null, ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)),
});

const image = (req) => (req.file ? req.file.path : null);

function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

app.get("/login", (req, res) => res.sendFile(path.join(ROOT, "public/login.html")));
app.get("/api/auth/session", (req, res) => res.json({ user: user(req) || null }));

// --- API REGISTER ---
app.post("/api/auth/register", async (req, res) => {
  const username = clean(req.body.username, 40);
  const email = clean(req.body.email, 254).toLowerCase();
  const password = clean(req.body.password, 100);
  const prodi = clean(req.body.prodi, 120) || "Belum diatur";

  if (!username || username.length < 3)
    return res.status(400).json({ error: "Username minimal 3 karakter." });
  if (!emailOK(email))
    return res.status(400).json({ error: "Gunakan email kampus yang berakhiran @mail.unpad.ac.id." });
  if (!password || password.length < 6)
    return res.status(400).json({ error: "Password minimal 6 karakter." });

  try {
    const userId = crypto.createHash("sha256").update(username).digest("hex").slice(0, 32);
    const password_hash = hashPassword(password);

    await pool.query(
      "INSERT INTO profiles(user_id, username, email, password_hash, prodi) VALUES($1, $2, $3, $4, $5)",
      [userId, username, email, password_hash, prodi]
    );

    res.json({ ok: true, message: "Pendaftaran berhasil, silakan masuk." });
  } catch (err) {
    res.status(409).json({ error: "Username atau email sudah terdaftar." });
  }
});

// --- API LOGIN ---
app.post("/api/auth/login", async (req, res) => {
  const username = clean(req.body.username, 40);
  const password = clean(req.body.password, 100);

  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password wajib diisi." });
  }

  try {
    const result = await pool.query("SELECT * FROM profiles WHERE username = $1", [username]);
    const account = result.rows[0];

    if (!account || account.password_hash !== hashPassword(password)) {
      return res.status(400).json({ error: "Username atau password salah." });
    }

    req.session.user = {
      id: account.user_id,
      username: account.username,
      email: account.email,
    };

    res.json({ user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: "Terjadi kesalahan pada server." });
  }
});

app.post("/api/auth/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/profile", auth, async (req, res) => {
  try {
    const result = await pool.query("SELECT npm, username, prodi FROM profiles WHERE user_id = $1", [user(req).id]);
    res.json({ profile: result.rows[0] || null, user: user(req) });
  } catch {
    res.status(500).json({ error: "Gagal memuat profil." });
  }
});

app.post("/api/profile", auth, async (req, res) => {
  const u = user(req),
    npm = clean(req.body.npm, 30),
    username = clean(req.body.username, 40),
    prodi = clean(req.body.prodi, 120);
  if (!npm || !username || !prodi)
    return res.status(400).json({ error: "NPM, username, dan program studi wajib diisi." });
  if (!/^[0-9A-Za-z.-]{4,30}$/.test(npm))
    return res.status(400).json({ error: "Format NPM tidak valid (4–30 karakter)." });
  
  try {
    await pool.query(
      "UPDATE profiles SET npm = $1, username = $2, prodi = $3 WHERE user_id = $4",
      [npm, username, prodi, u.id]
    );
    res.json({ profile: { npm, username, prodi } });
  } catch {
    res.status(409).json({ error: "NPM atau username mungkin sudah digunakan." });
  }
});

app.get("/api/reports", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, user_id, reporter_name, prodi, category, title, description, location, image_url, status, created_at FROM reports ORDER BY created_at DESC LIMIT 60"
    );
    res.json({ reports: result.rows });
  } catch {
    res.json({ reports: [] });
  }
});

app.post("/api/reports", auth, upload.single("image"), async (req, res) => {
  const u = user(req),
    title = clean(req.body.title, 120),
    category = clean(req.body.category, 80),
    prodi = clean(req.body.prodi, 120),
    location = clean(req.body.location, 180),
    description = clean(req.body.description, 2500);
  if (!title || !category || !prodi || !location || !description)
    return res.status(400).json({ error: "Lengkapi semua kolom wajib." });
  
  const pResult = await pool.query("SELECT username FROM profiles WHERE user_id = $1", [u.id]);
  const p = pResult.rows[0];
  if (!p) return res.status(400).json({ error: "Lengkapi profil terlebih dahulu." });

  const r = {
    id: crypto.randomUUID(),
    reporter_name: p.username,
    prodi,
    category,
    title,
    description,
    location,
    image_url: image(req),
    status: "Menunggu",
    created_at: new Date().toISOString(),
  };

  await pool.query(
    "INSERT INTO reports(id, user_id, reporter_name, prodi, category, title, description, location, image_url, status) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    [r.id, u.id, r.reporter_name, r.prodi, r.category, r.title, r.description, r.location, r.image_url, r.status]
  );
  res.status(201).json({ report: r });
});

app.get("/api/items", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT id, user_id, username, kind, title, description, location, contact, image_url, status, created_at FROM lost_items WHERE status='Aktif' ORDER BY created_at DESC LIMIT 100"
    );
    res.json({ items: result.rows });
  } catch {
    res.json({ items: [] });
  }
});

app.post("/api/items", auth, upload.single("image"), async (req, res) => {
  const u = user(req),
    kind = clean(req.body.kind, 20),
    title = clean(req.body.title, 120),
    description = clean(req.body.description, 1800),
    location = clean(req.body.location, 180),
    contact = clean(req.body.contact, 160);
  if (!["Hilang", "Ditemukan"].includes(kind) || !title || !description || !location || !contact)
    return res.status(400).json({ error: "Lengkapi semua kolom wajib." });
  
  const pResult = await pool.query("SELECT username FROM profiles WHERE user_id = $1", [u.id]);
  const p = pResult.rows[0];
  if (!p) return res.status(400).json({ error: "Lengkapi profil terlebih dahulu." });

  const i = {
    id: crypto.randomUUID(),
    username: p.username,
    kind,
    title,
    description,
    location,
    contact,
    image_url: image(req),
    status: "Aktif",
    created_at: new Date().toISOString(),
  };

  await pool.query(
    "INSERT INTO lost_items(id, user_id, username, kind, title, description, location, contact, image_url, status) VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    [i.id, u.id, i.username, i.kind, i.title, i.description, i.location, i.contact, i.image_url, i.status]
  );
  res.status(201).json({ item: i });
});


// --- API HAPUS LAPORAN ---
app.delete("/api/reports/:id", auth, async (req, res) => {
  try {
    const check = await pool.query("SELECT * FROM reports WHERE id = $1 AND user_id = $2", [req.params.id, user(req).id]);
    if (check.rows.length === 0) return res.status(403).json({ error: "Tidak berhak menghapus." });
    
    await pool.query("DELETE FROM reports WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Gagal menghapus laporan." });
  }
});

// --- API HAPUS BARANG HILANG ---
app.delete("/api/items/:id", auth, async (req, res) => {
  try {
    const check = await pool.query("SELECT * FROM lost_items WHERE id = $1 AND user_id = $2", [req.params.id, user(req).id]);
    if (check.rows.length === 0) return res.status(403).json({ error: "Tidak berhak menghapus." });
    
    await pool.query("DELETE FROM lost_items WHERE id = $1", [req.params.id]);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Gagal menghapus postingan." });
  }
});

app.use((err, req, res, next) =>

  res.status(400).json({
    error: err.code === "LIMIT_FILE_SIZE" ? "Ukuran foto maksimal 5 MB." : err.message || "Terjadi kesalahan.",
  })
);

app.listen(PORT, () => console.log("PorUnpad v6 PostgreSQL berjalan di http://localhost:" + PORT));