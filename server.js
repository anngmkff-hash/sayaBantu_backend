// ============================
// server.js (FINAL)
// ============================
const path = require("path");
require("dotenv").config({ path: path.join(__dirname, ".env"), override: true });

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const fs = require("fs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const app = express();
const port = process.env.PORT || 5000;

// ============================
// SMTP
// ============================
const SMTP_PORT_NUM = Number(process.env.SMTP_PORT) || 465;
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || "smtp.gmail.com",
  port: SMTP_PORT_NUM,
  secure: SMTP_PORT_NUM === 465,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  requireTLS: SMTP_PORT_NUM !== 465,
  tls: { minVersion: "TLSv1.2" },
});

transporter.verify((err, ok) => {
  if (err) console.error("SMTP error:", err.message);
  else console.log("SMTP ready?", ok);
});

async function sendResetEmail(to, link) {
  const from = process.env.SMTP_FROM || `Support <${process.env.SMTP_USER}>`;
  return transporter.sendMail({
    from,
    to,
    subject: "Reset Password",
    html: `
      <p>Anda meminta reset password.</p>
      <p>Link (berlaku 30 menit): <a href="${link}">${link}</a></p>
      <p>Abaikan jika Anda tidak meminta reset.</p>
    `,
  });
}

// ============================
// DB (pakai .env)
// ============================
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  connectionLimit: 10,
});

db.getConnection((err, conn) => {
  if (err) throw err;
  console.log("Connected to MySQL");
  conn.release();
});

const q = (sql, params = []) =>
  db.promise().query(sql, params).then(([rows]) => rows);

const sendDbError = (res, err, label) => {
  console.error(`[${label}]`, {
    message: err?.message || err?.sqlMessage,
    sql: err?.sql,
  });
  res.status(500).json({
    error: "Database error",
    detail: err?.sqlMessage || err?.message,
  });
};

// ============================
// Middlewares
// ============================
app.use(cors());
app.use(express.json());

// uploads
const uploadsDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use("/uploads", express.static(uploadsDir));

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// ============================
// Auth helpers
// ============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });

  jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}
const adminOnly = (req, res, next) =>
  req.user?.role === "admin"
    ? next()
    : res.status(403).json({ error: "Access denied: Admins only" });

// ============================
// Utils
// ============================
const btoi = (v) => (v ? 1 : 0);
const num = (v, d = 0) =>
  v === undefined || v === null || v === "" ? d : Number(v);

// ============================
// SETTINGS helpers
// ============================
async function getPrimaryLogoUrl() {
  const rows = await q(
    "SELECT url FROM logos WHERE placement='header' AND is_primary=1 AND is_active=1 ORDER BY id DESC LIMIT 1"
  );
  return rows[0]?.url || "";
}
async function getPrimaryWaFull() {
  const rows = await q(
    "SELECT phone, whatsapp_message FROM whatsapp_numbers WHERE is_primary=1 AND is_active=1 ORDER BY id DESC LIMIT 1"
  );
  return rows[0] || { phone: "", whatsapp_message: "" };
}

// ============================
// SETTINGS routes (admin)
// ============================
app.get("/settings", authenticateToken, adminOnly, async (req, res) => {
  try {
    const logo_url = await getPrimaryLogoUrl();
    const wa = await getPrimaryWaFull();
    res.json({
      logo_url,
      whatsapp_number: wa.phone || "",
      whatsapp_message: wa.whatsapp_message || "",
    });
  } catch (e) {
    sendDbError(res, e, "GET /settings");
  }
});

app.put("/settings/whatsapp", authenticateToken, adminOnly, async (req, res) => {
  try {
    const { whatsapp_number, whatsapp_message } = req.body;
    if (!whatsapp_number || !whatsapp_message)
      return res.status(400).json({ error: "Data tidak lengkap" });

    const rows = await q(
      "SELECT id FROM whatsapp_numbers WHERE is_primary=1 LIMIT 1"
    );
    if (rows.length) {
      await q(
        "UPDATE whatsapp_numbers SET phone=?, whatsapp_message=?, is_active=1 WHERE id=?",
        [whatsapp_number, whatsapp_message, rows[0].id]
      );
    } else {
      await q(
        "INSERT INTO whatsapp_numbers (label, phone, whatsapp_message, is_primary, is_active) VALUES ('umum', ?, ?, 1, 1)",
        [whatsapp_number, whatsapp_message]
      );
    }
    res.json({ ok: true });
  } catch (e) {
    sendDbError(res, e, "PUT /settings/whatsapp");
  }
});

// ============================
// SERVICES (admin) — SATU GET (tidak duplikat)
// ============================
app.get("/services", authenticateToken, adminOnly, async (req, res) => {
  try {
    const rows = await q("SELECT * FROM services ORDER BY sort_order ASC, id ASC");
    res.json(rows);
  } catch (e) {
    sendDbError(res, e, "GET /services");
  }
});

app.post(
  "/services",
  authenticateToken,
  adminOnly,
  upload.single("icon_file"),
  async (req, res) => {
    try {
      const {
        name,
        short_name,
        slug,
        summary,
        description,
        icon_type,
        icon_bg,
        price_min,
        price_unit,
        is_popular,
        is_active,
        sort_order,
      } = req.body;

      if (!name || !slug)
        return res.status(400).json({ error: "Name & slug wajib" });

      let iconValue = "";
      if (req.file) iconValue = `/uploads/${req.file.filename}`;

      const r = await q(
        `INSERT INTO services
         (name, short_name, slug, summary, description, icon_type, icon_value, icon_bg, price_min, price_unit, is_popular, is_active, sort_order)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [
          name,
          short_name || null,
          slug,
          summary || null,
          description || null,
          icon_type || "image",
          iconValue,
          icon_bg || null,
          num(price_min, null),
          price_unit || null,
          btoi(is_popular),
          btoi(is_active ?? 1),
          num(sort_order, 0),
        ]
      );
      res.status(201).json({ ok: true, serviceId: r.insertId });
    } catch (e) {
      sendDbError(res, e, "POST /services");
    }
  }
);

// ============================
// PUBLIC
// ============================
app.get("/public/site", async (req, res) => {
  try {
    const logo = await getPrimaryLogoUrl();
    const wa = await getPrimaryWaFull();
    const emails = await q(
      "SELECT id,label,email,is_primary,is_active FROM emails WHERE is_active=1 ORDER BY is_primary DESC, id ASC"
    );
    const addresses = await q(
      "SELECT id,label,address_line,city,province,postal_code,maps_url,is_primary,is_active FROM addresses WHERE is_active=1 ORDER BY is_primary DESC, id ASC"
    );
    const socials = await q(
      "SELECT id,platform,handle,url,icon_type,icon_value,sort_order,is_active FROM social_links WHERE is_active=1 ORDER BY sort_order ASC, id ASC"
    );
    res.json({
      logo_url: logo || "",
      whatsapp_number: wa.phone || "",
      whatsapp_message: wa.whatsapp_message ?? "",
      emails,
      addresses,
      socials,
    });
  } catch (e) {
    sendDbError(res, e, "GET /public/site");
  }
});

app.get("/public/services", async (req, res) => {
  try {
    const rows = await q(
      "SELECT id,name,slug,summary,icon_type,icon_value,icon_bg,is_popular FROM services WHERE is_active=1 ORDER BY sort_order ASC, name ASC"
    );
    res.json(rows);
  } catch (e) {
    sendDbError(res, e, "GET /public/services");
  }
});

// ============================
// AUTH
// ============================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email & password wajib" });

  try {
    const rows = await q("SELECT * FROM users WHERE email=?", [email]);
    if (!rows.length)
      return res.status(400).json({ error: "Invalid credentials" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password);
    if (!ok)
      return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role },
    });
  } catch (e) {
    sendDbError(res, e, "POST /login");
  }
});

// ============================
// PASSWORD RESET
// ============================
app.post("/auth/request-reset", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const generic = { message: "Jika email terdaftar, link reset telah dikirim." };
  if (!email) return res.json(generic);

  try {
    const rows = await q(
      "SELECT id,email FROM users WHERE LOWER(email)=? LIMIT 1",
      [email]
    );
    if (!rows.length) return res.json(generic);

    const user = rows[0];
    await q("DELETE FROM password_reset_tokens WHERE user_id=?", [user.id]);

    const plain = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(plain).digest("hex");

    await q(
      "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, created_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 30 MINUTE), NOW())",
      [user.id, tokenHash]
    );

    const link = `${process.env.APP_URL}/reset-password?token=${plain}`;
    await sendResetEmail(user.email, link).catch(() => {});
    res.json(generic);
  } catch (e) {
    sendDbError(res, e, "POST /auth/request-reset");
  }
});

app.post("/auth/reset-password", async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password)
    return res.status(400).json({ error: "Token & password wajib" });

  try {
    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
    const rows = await q(
      "SELECT user_id FROM password_reset_tokens WHERE token_hash=? AND expires_at > NOW() LIMIT 1",
      [tokenHash]
    );
    if (!rows.length)
      return res.status(400).json({ error: "Token tidak valid/kedaluwarsa" });

    const hash = await bcrypt.hash(password, 10);
    await q("UPDATE users SET password=? WHERE id=?", [
      hash,
      rows[0].user_id,
    ]);
    await q("DELETE FROM password_reset_tokens WHERE user_id=?", [
      rows[0].user_id,
    ]);
    res.json({ message: "Password berhasil direset" });
  } catch (e) {
    sendDbError(res, e, "POST /auth/reset-password");
  }
});

// ============================
// Start
// ============================
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
