const express = require("express"),
  session = require("express-session"),
  multer = require("multer"),
  path = require("path"),
  fs = require("fs"),
  crypto = require("crypto"),
  Database = require("better-sqlite3"),
  nodemailer = require("nodemailer"); // <-- Modul Nodemailer ditambahkan

const app = express(),
  PORT = process.env.PORT || 3000,
  ROOT = __dirname,
  UPLOAD = path.join(ROOT, "public/uploads"),
  DATA = path.join(ROOT, "data");

fs.mkdirSync(UPLOAD, { recursive: true });
fs.mkdirSync(DATA, { recursive: true });

const db = new Database(path.join(DATA, "porunpad.db"));
db.pragma("journal_mode=WAL");

db.exec(`CREATE TABLE IF NOT EXISTS profiles(user_id TEXT PRIMARY KEY,email TEXT UNIQUE NOT NULL,npm TEXT UNIQUE,username TEXT NOT NULL,prodi TEXT NOT NULL,created_at TEXT DEFAULT(datetime('now')));
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

const pending = new Map(),
  emailOK = (e) => /^[^\s@]+@mail\.unpad\.ac\.id$/i.test(String(e || "")),
  clean = (v, n = 2500) => String(v ?? "").trim().slice(0, n),
  uid = () => crypto.randomUUID(),
  user = (req) => req.session.user;

function auth(req, res, next) {
  if (!user(req))
    return res.status(401).json({ error: "Masuk dengan email kampus terlebih dahulu." });
  if (!emailOK(user(req).email))
    return res.status(403).json({ error: "Gunakan email kampus @mail.unpad.ac.id." });
  next();
}

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD,
    filename: (req, file, cb) => {
      const ext = {
        "image/jpeg": ".jpg",
        "image/png": ".png",
        "image/webp": ".webp",
      }[file.mimetype];
      if (!ext) return cb(new Error("Format foto harus JPG, PNG, atau WebP."));
      cb(null, Date.now() + "-" + crypto.randomBytes(5).toString("hex") + ext);
    },
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    cb(null, ["image/jpeg", "image/png", "image/webp"].includes(file.mimetype)),
});

const image = (req) => (req.file ? "/uploads/" + req.file.filename : null);

// --- KONFIGURASI PENGIRIM EMAIL NODEMAILER ---
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true, // Gunakan koneksi SSL yang diwajibkan Google
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    // Membantu mencegah error jaringan internal di beberapa server cloud
    rejectUnauthorized: false
  }
});

app.get("/login", (req, res) => res.sendFile(path.join(ROOT, "public/login.html")));
app.get("/api/auth/session", (req, res) => res.json({ user: user(req) || null }));

// --- API AUTH START (YANG DIPERBARUI UNTUK MENGIRIM EMAIL OTP) ---
app.post("/api/auth/start", async (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase();
  if (!emailOK(email))
    return res.status(400).json({ error: "Gunakan email kampus yang berakhiran @mail.unpad.ac.id." });
  
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, "0");
  pending.set(email, { code, expires: Date.now() + 600000, attempts: 0 });

  const mailOptions = {
    from: `"PorUnpad" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Kode OTP Login PorUnpad",
    text: `Halo,\n\nKode OTP Anda adalah: ${code}\n\nKode ini akan kedaluwarsa dalam 10 menit. Mohon jangan berikan kode ini kepada siapa pun.`,
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log(`[PorUnpad OTP] Berhasil mengirim OTP ke ${email}`);
    res.json({ ok: true });
  } catch (error) {
    console.error("[PorUnpad OTP Error] Gagal mengirim email:", error);
    res.status(500).json({ error: "Gagal mengirim kode OTP ke email. Pastikan konfigurasi email di Render sudah benar." });
  }
});

app.post("/api/auth/verify", (req, res) => {
  const email = clean(req.body.email, 254).toLowerCase(),
    code = clean(req.body.code, 6),
    p = pending.get(email);
  if (!p || Date.now() > p.expires || p.attempts >= 5 || p.code !== code) {
    if (p) p.attempts++;
    return res.status(400).json({ error: "Kode salah atau kedaluwarsa. Minta kode baru." });
  }
  pending.delete(email);
  req.session.user = {
    id: crypto.createHash("sha256").update(email).digest("hex").slice(0, 32),
    email,
    name: email.split("@")[0],
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
      "INSERT INTO profiles(user_id,email,npm,username,prodi) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET npm=excluded.npm,username=excluded.username,prodi=excluded.prodi"
    ).run(u.id, u.email, npm, username, prodi);
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
    id: uid(),
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
    id: uid(),
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
