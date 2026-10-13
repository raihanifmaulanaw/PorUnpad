const express = require("express"),
  session = require("express-session"),
  multer = require("multer"),
  path = require("path"),
  fs = require("fs"),
  crypto = require("crypto"),
  Database = require("better-sqlite3");

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
  ROOT = __dirname,
  DATA = path.join(ROOT, "data");

fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, "porunpad.db"));
db.pragma("journal_mode=WAL");

// Tabel profiles ditambah kolom password_hash
db.exec(`CREATE TABLE IF NOT EXISTS profiles(
  user_id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  npm TEXT UNIQUE,
  username TEXT NOT NULL,
  prodi TEXT NOT NULL,
  created_at TEXT DEFAULT(datetime('now'))
);
CREATE TABLE IF NOT EXISTS reports(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,reporter_name TEXT NOT NULL,prodi TEXT NOT NULL,category TEXT NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL,location TEXT NOT NULL,image_url TEXT,status TEXT DEFAULT 'Menunggu',created_at TEXT DEFAULT(datetime('now')));
CREATE TABLE IF NOT EXISTS lost_items(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,username TEXT NOT NULL,kind TEXT NOT NULL,title TEXT NOT NULL,description TEXT NOT NULL,location TEXT NOT NULL,contact TEXT NOT NULL,image_url TEXT,status TEXT DEFAULT 'Aktif',created_at TEXT DEFAULT(datetime('now')));`);

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
    return res.status(401).json({ error: "Masuk dengan email kampus terlebih dahulu." });
  if (!emailOK(user(req).email))
    return res.status(403).json({ error: "Gunakan email kampus @mail.unpad.ac.id." });
  next();
}

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    cb(null, ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)),
});

const image = (req) => (req.file ? req.file.path : null);

// Fungsi pembantu hash password sederhana
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

app.get("/login", (req, res) => res.sendFile(path.join(ROOT, "public/login.html")));
app.get("/api/auth/session", (req, res) => res.json({ user: user(req) || null }));

// --- API REGISTER (Daftar Akun Baru dengan Password) ---
app.post("/api/auth/register", (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  const password = clean(req.body.password, 100);
  const username = clean(req.body.username, 40) || email.split("@")[0];
  const prodi = clean(req.body.prodi, 120) || "Belum diatur";

  if (!emailOK(email))
    return res.status(400).json({ error: "Gunakan email kampus yang berakhiran @mail.unpad.ac.id." });
  if (!password || password.length < 6)
    return res.status(400).json({ error: "Password minimal 6 karakter." });

  try {
    const userId = crypto.createHash("sha256").update(email).digest("hex").slice(0, 32);
    const password_hash = hashPassword(password);

    db.prepare(
      "INSERT INTO profiles(user_id, email, password_hash, username, prodi) VALUES(?, ?, ?, ?, ?)"
    ).run(userId, email, password_hash, username, prodi);

    res.json({ ok: true, message: "Pendaftaran berhasil, silakan login." });
  } catch (err) {
    res.status(409).json({ error: "Email sudah terdaftar. Silakan langsung masuk." });
  }
});

// --- API LOGIN (Masuk dengan Email & Password) ---
app.post("/api/auth/login", (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  const password = clean(req.body.password, 100);

  if (!emailOK(email))
    return res.status(400).json({ error: "Gunakan email kampus @mail.unpad.ac.id." });

  const account = db.prepare("SELECT * FROM profiles WHERE email = ?").get(email);

  if (!account || account.password_hash !== hashPassword(password)) {
    return res.status(400).json({ error: "Email atau password salah." });
  }

  req.session.user = {
    id: account.user_id,
    email: account.email,
    name: account.username,
  };

  res.json({ user: req.session.user });
});

app.post("/api/auth/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));

app.get("/api/profile", auth, (req, res) =>
  res.json({
    profile: db.prepare("SELECT npm,username,prodi FROM profiles WHERE user_id=?").get(user(req).id) || null,
    user: user(req),
  })
);

app.post("/api/profile", auth, (req, res) => {
  const u = user(req),
    npm = clean(req.body.npm, 30),
    username = clean(req.body.username, 40),
    prodi = clean(req.body.prodi, 120);
  if (!npm || !username || !prodi)
    return res.status(400).json({ error: "NPM, username, dan program studi wajib diisi." });
  if (!/^[0-9A-Za-z.-]{4,30}$/.test(npm))
    return res.status(400).json({ error: "Format NPM tidak valid (4–30 karakter)." });
  if (!/^[\p{L}0-9_.-]{3,40}$/u.test(username))
    return res.status(400).json({ error: "Username harus 3–40 karakter." });
  try {
    db.prepare(
      "UPDATE profiles SET npm=?, username=?, prodi=? WHERE user_id=?"
    ).run(npm, username, prodi, u.id);
    res.json({ profile: { npm, username, prodi } });
  } catch {
    res.status(409).json({ error: "NPM mungkin sudah terdaftar." });
  }
});

app.get("/api/reports", (req, res) =>
  res.json({
    reports: db
      .prepare(
        "SELECT id,reporter_name,prodi,category,title,description,location,image_url,status,created_at FROM reports ORDER BY created_at DESC LIMIT 60"
      )
      .all(),
  })
);

app.post("/api/reports", auth, upload.single("image"), (req, res) => {
  const u = user(req),
    title = clean(req.body.title, 120),
    category = clean(req.body.category, 80),
    prodi = clean(req.body.prodi, 120),
    location = clean(req.body.location, 180),
    description = clean(req.body.description, 2500);
  if (!title || !category || !prodi || !location || !description)
    return res.status(400).json({ error: "Lengkapi semua kolom wajib." });
  const p = db.prepare("SELECT username FROM profiles WHERE user_id=?").get(u.id);
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
  db.prepare(
    "INSERT INTO reports(id,user_id,reporter_name,prodi,category,title,description,location,image_url,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
  ).run(
    r.id,
    u.id,
    r.reporter_name,
    r.prodi,
    r.category,
    r.title,
    r.description,
    r.location,
    r.image_url,
    r.status,
    r.created_at
  );
  res.status(201).json({ report: r });
});

app.get("/api/items", (req, res) =>
  res.json({
    items: db
      .prepare(
        "SELECT id,username,kind,title,description,location,contact,image_url,status,created_at FROM lost_items WHERE status='Aktif' ORDER BY created_at DESC LIMIT 100"
      )
      .all(),
  })
);

app.post("/api/items", auth, upload.single("image"), (req, res) => {
  const u = user(req),
    kind = clean(req.body.kind, 20),
    title = clean(req.body.title, 120),
    description = clean(req.body.description, 1800),
    location = clean(req.body.location, 180),
    contact = clean(req.body.contact, 160);
  if (!["Hilang", "Ditemukan"].includes(kind) || !title || !description || !location || !contact)
    return res.status(400).json({ error: "Lengkapi semua kolom wajib." });
  const p = db.prepare("SELECT username FROM profiles WHERE user_id=?").get(u.id);
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
  db.prepare(
    "INSERT INTO lost_items(id,user_id,username,kind,title,description,location,contact,image_url,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)"
  ).run(
    i.id,
    u.id,
    i.username,
    i.kind,
    i.title,
    i.description,
    i.location,
    i.contact,
    i.image_url,
    i.status,
    i.created_at
  );
  res.status(201).json({ item: i });
});

app.use((err, req, res, next) =>
  res.status(400).json({
    error: err.code === "LIMIT_FILE_SIZE" ? "Ukuran foto maksimal 5 MB." : err.message || "Terjadi kesalahan.",
  })
);

app.listen(PORT, () => console.log("PorUnpad v5 berjalan di http://localhost:" + PORT));
