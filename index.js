import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import jwt from "jsonwebtoken";
import process from "node:process";
import dotenv from "dotenv";
dotenv.config();

const app = express();
const allowedOrigins = (process.env.CORS_ALLOW_ORIGINS || "http://localhost:5173,http://localhost:5174, https://drawdb-diagram.shovickbarua.com")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);
app.use(cors({
  origin: (origin, cb) => { if (!origin || allowedOrigins.includes(origin)) return cb(null, true); cb(new Error("Not allowed by CORS")); },
  methods: ["GET","POST","PUT","DELETE","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization"]
}));
app.use(express.json({ limit: "2mb" }));

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const AUTH_MODE = process.env.AUTH_MODE || "static"; // "none" | "static" | "jwt"
const API_TOKEN = process.env.API_TOKEN || "dev-token";
const PORT = process.env.PORT || 5179;
const diagramsDir = process.env.DIAGRAMS_DIR || path.join(process.cwd(), "public", "diagrams");
if (!fs.existsSync(diagramsDir)) fs.mkdirSync(diagramsDir, { recursive: true });

let USERS = null;
if (AUTH_MODE === "jwt") {
  USERS = [{ username: "admin", password: process.env.ADMIN_PASSWORD || "admin" }];
}

function auth(req, res, next) {
  if (AUTH_MODE === "none") return next();
  const authHeader = req.headers.authorization || "";
  if (AUTH_MODE === "static") {
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (token && token === API_TOKEN) return next();
    return res.status(401).json({ error: "unauthorized" });
  }
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "unauthorized" });
  try { jwt.verify(token, JWT_SECRET); next(); } catch { return res.status(401).json({ error: "invalid_token" }); }
}

function safeFile(name) {
  const base = String(name || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 128);
  return (base || "untitled") + ".json";
}

app.get("/health", (_req, res) => res.json({ ok: true }));

app.post("/api/login", (req, res) => {
  if (AUTH_MODE === "none") return res.json({ token: null });
  if (AUTH_MODE === "static") return res.json({ token: API_TOKEN });
  const { username, password } = req.body || {};
  const user = USERS && USERS.find(u => u.username === username);
  if (!user || (password || "") !== user.password) return res.status(401).json({ error: "invalid_credentials" });
  const token = jwt.sign({ sub: username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token });
});

app.get("/api/projects", auth, (_req, res) => {
  try {
    const files = fs.readdirSync(diagramsDir).filter((f) => f.toLowerCase().endsWith(".json"));
    res.json({ files });
  } catch {
    res.status(500).json({ error: "list_failed" });
  }
});

app.get("/api/projects/:name", auth, (req, res) => {
  try {
    const name = safeFile(req.params.name);
    const p = path.join(diagramsDir, name);
    if (!fs.existsSync(p)) return res.status(404).json({ error: "not_found" });
    const text = fs.readFileSync(p, "utf8");
    res.type("application/json").send(text);
  } catch {
    res.status(500).json({ error: "read_failed" });
  }
});

app.post("/api/projects", auth, (req, res) => {
  try {
    const { name, content } = req.body || {};
    if (!name) return res.status(400).json({ error: "name_required" });
    const file = safeFile(name);
    const p = path.join(diagramsDir, file);
    if (fs.existsSync(p)) return res.status(409).json({ error: "exists" });
    fs.writeFileSync(p, JSON.stringify(content ?? {}, null, 2));
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "create_failed" });
  }
});

app.put("/api/projects/:name", auth, (req, res) => {
  try {
    const { content } = req.body || {};
    const file = safeFile(req.params.name);
    const p = path.join(diagramsDir, file);
    fs.writeFileSync(p, JSON.stringify(content ?? {}, null, 2));
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "save_failed" });
  }
});

app.delete("/api/projects/:name", auth, (req, res) => {
  try {
    const file = safeFile(req.params.name);
    const p = path.join(diagramsDir, file);
    if (!fs.existsSync(p)) return res.status(404).json({ error: "not_found" });
    fs.unlinkSync(p);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "delete_failed" });
  }
});

app.listen(PORT, () => { console.log(`Server running at http://localhost:${PORT}`); });
