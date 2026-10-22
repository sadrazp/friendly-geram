require("dotenv").config();
const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const helmet = require("helmet");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === "production";
const dataDir = path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error("SESSION_SECRET must be set in .env and be at least 32 characters.");
  process.exit(1);
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD === "replace-with-a-unique-strong-password") {
  console.error("Set ADMIN_USERNAME and a unique ADMIN_PASSWORD in .env before starting.");
  process.exit(1);
}
if (production && process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);

const db = new Database(path.join(dataDir, "friendly-geram.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin','user')),
 active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 display_name TEXT,
 avatar_data TEXT,
 language TEXT NOT NULL DEFAULT 'fa'
);
CREATE TABLE IF NOT EXISTS messages (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 sender_id INTEGER NOT NULL REFERENCES users(id),
 recipient_id INTEGER NOT NULL REFERENCES users(id),
 body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 4000),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 chat_type TEXT NOT NULL DEFAULT 'private',
 chat_id INTEGER,
 reply_to INTEGER,
 edited_at TEXT,
 pinned INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS chats (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
 description TEXT NOT NULL DEFAULT '',
 type TEXT NOT NULL CHECK(type IN ('group','channel')),
 creator_id INTEGER NOT NULL REFERENCES users(id),
 invite_token TEXT NOT NULL UNIQUE,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS chat_members (
 chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('owner','admin','member')),
 joined_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(chat_id,user_id)
);
CREATE TABLE IF NOT EXISTS reactions (
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 emoji TEXT NOT NULL,
 PRIMARY KEY(message_id,user_id,emoji)
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, recipient_id, id);
CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, id);
`);

// Safe migrations for databases created by earlier versions.
const ensureColumn = (table, name, definition) => {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(name)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
};
ensureColumn("users", "display_name", "TEXT");
ensureColumn("users", "avatar_data", "TEXT");
ensureColumn("users", "language", "TEXT NOT NULL DEFAULT 'fa'");
ensureColumn("messages", "chat_type", "TEXT NOT NULL DEFAULT 'private'");
ensureColumn("messages", "chat_id", "INTEGER");
ensureColumn("messages", "reply_to", "INTEGER");
ensureColumn("messages", "edited_at", "TEXT");
ensureColumn("messages", "pinned", "INTEGER NOT NULL DEFAULT 0");

const adminName = String(process.env.ADMIN_USERNAME).trim();
const adminPassword = String(process.env.ADMIN_PASSWORD);
if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(adminName)) {
  console.error("ADMIN_USERNAME must be 3-32 characters: letters, numbers, dot, underscore or hyphen.");
  process.exit(1);
}
const existingAdmin = db.prepare("SELECT id FROM users WHERE username = ? COLLATE NOCASE").get(adminName);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(adminPassword, 12);
  db.prepare("INSERT INTO users (username,password_hash,role) VALUES (?,?, 'admin')").run(adminName, hash);
  console.log(`Initial admin created: ${adminName}`);
} else {
  console.log(`Admin account already exists: ${adminName} (password is not reset automatically)`);
}

const SQLiteStore = SQLiteStoreFactory(session);
const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, table: "sessions" }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "fg.sid",
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: production,
    maxAge: 1000 * 60 * 60 * 8
  }
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.socket.io", "https://cdn.jsdelivr.net"],
      workerSrc: ["'self'", "blob:"],
      styleSrc: ["'self'"],
      connectSrc: ["'self'", "ws:", "wss:"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      upgradeInsecureRequests: production ? [] : null
    }
  }
}));
app.use(express.json({ limit: "3mb" }));
app.use(express.urlencoded({ extended: false, limit: "8kb" }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public"), { index: false, maxAge: production ? "1h" : 0 }));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const createLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });

function currentUser(req) {
  if (!req.session.userId) return null;
  return db.prepare("SELECT id, username, role, active, display_name, avatar_data, language FROM users WHERE id = ?").get(req.session.userId) || null;
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user || !user.active) {
    return res.status(401).json({ error: "ابتدا وارد حساب شوید." });
  }
  req.user = user;
  next();
}
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") return res.status(403).json({ error: "دسترسی مدیر لازم است." });
  next();
}
function csrfCheck(req, res, next) {
  const supplied = req.get("x-csrf-token");
  if (!req.session.csrfToken || supplied !== req.session.csrfToken) {
    return res.status(403).json({ error: "درخواست نامعتبر است. صفحه را تازه‌سازی کنید." });
  }
  next();
}
function safeUser(u) {
  return { id: u.id, username: u.username, role: u.role, active: !!u.active, displayName: u.display_name || u.displayName || u.username, avatarData: u.avatar_data || u.avatarData || null, language: u.language || "fa" };
}

app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/api/session", (req, res) => {
  const user = currentUser(req);
  if (user && user.active && !req.session.csrfToken) {
    req.session.csrfToken = require("crypto").randomBytes(32).toString("hex");
  }
  res.json({ user: user && user.active ? safeUser(user) : null, csrfToken: req.session.csrfToken || null });
});
app.post("/api/login", loginLimiter, async (req, res, next) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");
    if (!username || !password || username.length > 32 || password.length > 200) {
      return res.status(400).json({ error: "نام کاربری یا رمز عبور نامعتبر است." });
    }
    const user = db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username);
    const valid = user && user.active && await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.userId = user.id;
      req.session.csrfToken = require("crypto").randomBytes(32).toString("hex");
      req.session.save(err2 => {
        if (err2) return next(err2);
        res.json({ user: safeUser(user), csrfToken: req.session.csrfToken });
      });
    });
  } catch (e) { next(e); }
});
app.post("/api/logout", requireAuth, csrfCheck, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("fg.sid", { httpOnly: true, sameSite: "strict", secure: production });
    res.json({ ok: true });
  });
});
app.get("/api/users", requireAuth, (req, res) => {
  const users = db.prepare("SELECT id, username, role, active, display_name, avatar_data, language FROM users WHERE active=1 AND id<>? ORDER BY username").all(req.user.id);
  res.json({ users });
});
app.get("/api/messages/:userId", requireAuth, (req, res) => {
  const otherId = Number(req.params.userId);
  if (!Number.isSafeInteger(otherId) || otherId < 1) return res.status(400).json({ error: "شناسه نامعتبر است." });
  const other = db.prepare("SELECT id FROM users WHERE id=? AND active=1").get(otherId);
  if (!other) return res.status(404).json({ error: "کاربر پیدا نشد." });
  const messages = db.prepare(`
    SELECT m.id, m.sender_id AS senderId, m.recipient_id AS recipientId,
      m.body, m.created_at AS createdAt, m.reply_to AS replyTo, m.edited_at AS editedAt, m.pinned, s.username AS senderUsername,
      (SELECT json_group_array(json_object('emoji',r.emoji,'userId',r.user_id)) FROM reactions r WHERE r.message_id=m.id) AS reactions
    FROM messages m JOIN users s ON s.id=m.sender_id
    WHERE m.chat_type='private' AND ((m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?))
    ORDER BY m.id DESC LIMIT 200
  `).all(req.user.id, otherId, otherId, req.user.id).reverse().map(m=>({...m,pinned:!!m.pinned,reactions:JSON.parse(m.reactions||"[]")}));
  res.json({ messages });
});
app.post("/api/messages", requireAuth, csrfCheck, (req, res) => {
  const recipientId = Number(req.body.recipientId);
  const body = String(req.body.body || "").trim();
  if (!Number.isSafeInteger(recipientId) || recipientId < 1 || body.length < 1 || body.length > 4000) {
    return res.status(400).json({ error: "پیام یا گیرنده نامعتبر است (حداکثر ۴۰۰۰ نویسه)." });
  }
  const recipient = db.prepare("SELECT id FROM users WHERE id=? AND active=1").get(recipientId);
  if (!recipient || recipientId === req.user.id) return res.status(400).json({ error: "گیرنده نامعتبر است." });
  const replyTo=req.body.replyTo ? Number(req.body.replyTo) : null;
  if(replyTo && !db.prepare("SELECT id FROM messages WHERE id=? AND chat_type='private' AND ((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?))").get(replyTo,req.user.id,recipientId,recipientId,req.user.id)) return res.status(400).json({error:"پیام برای پاسخ پیدا نشد."});
  const result = db.prepare("INSERT INTO messages (sender_id, recipient_id, body, reply_to) VALUES (?,?,?,?)").run(req.user.id, recipientId, body, replyTo);
  const message = db.prepare(`
    SELECT m.id, m.sender_id AS senderId, m.recipient_id AS recipientId,
      m.body, m.created_at AS createdAt, m.reply_to AS replyTo, m.edited_at AS editedAt, m.pinned, s.username AS senderUsername
    FROM messages m JOIN users s ON s.id=m.sender_id WHERE m.id=?
  `).get(result.lastInsertRowid);
  io.to(`user:${recipientId}`).emit("message", message);
  io.to(`user:${req.user.id}`).emit("message", message);
  res.status(201).json({ message });
});

// Profile, language, groups/channels, invitations and message tools.
app.get("/api/profile", requireAuth, (req, res) => {
  const u = db.prepare("SELECT id,username,role,active,display_name,avatar_data,language FROM users WHERE id=?").get(req.user.id);
  res.json({ user: safeUser(u) });
});
app.patch("/api/profile", requireAuth, csrfCheck, (req, res) => {
  const displayName = String(req.body.displayName || "").trim().slice(0, 40);
  const language = ["fa", "en"].includes(req.body.language) ? req.body.language : "fa";
  const avatarData = req.body.avatarData === null ? null : String(req.body.avatarData || "");
  if (avatarData && (!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatarData) || avatarData.length > 1800000)) {
    return res.status(400).json({ error: "عکس باید PNG/JPEG/WEBP/GIF و کمتر از حدود ۱٫۳ مگابایت باشد." });
  }
  db.prepare("UPDATE users SET display_name=?, avatar_data=?, language=? WHERE id=?")
    .run(displayName || req.user.username, avatarData || null, language, req.user.id);
  const u = db.prepare("SELECT id,username,role,active,display_name,avatar_data,language FROM users WHERE id=?").get(req.user.id);
  res.json({ user: safeUser(u) });
});
function chatForMember(chatId, userId) {
  return db.prepare(`SELECT c.*, cm.role AS memberRole FROM chats c JOIN chat_members cm ON cm.chat_id=c.id WHERE c.id=? AND cm.user_id=?`).get(chatId, userId);
}
app.get("/api/chats", requireAuth, (req, res) => {
  const chats = db.prepare(`SELECT c.id,c.name,c.description,c.type,c.creator_id AS creatorId,c.invite_token AS inviteToken,cm.role AS memberRole,
    (SELECT COUNT(*) FROM chat_members x WHERE x.chat_id=c.id) AS memberCount
    FROM chats c JOIN chat_members cm ON cm.chat_id=c.id WHERE cm.user_id=? ORDER BY c.id DESC`).all(req.user.id);
  res.json({ chats });
});
function createChat(req, res, type) {
  const name = String(req.body.name || "").trim().slice(0,80);
  const description = String(req.body.description || "").trim().slice(0,500);
  if (name.length < 1) return res.status(400).json({ error: "نام گروه/کانال را وارد کن." });
  const token = require("crypto").randomBytes(24).toString("hex");
  const result = db.prepare("INSERT INTO chats(name,description,type,creator_id,invite_token) VALUES(?,?,?,?,?)").run(name,description,type,req.user.id,token);
  db.prepare("INSERT INTO chat_members(chat_id,user_id,role) VALUES(?,?,'owner')").run(result.lastInsertRowid,req.user.id);
  for (const sock of io.sockets.sockets.values()) if (sock.user?.id === req.user.id) sock.join(`chat:${Number(result.lastInsertRowid)}`);
  res.status(201).json({ chat: { id:Number(result.lastInsertRowid),name,description,type,creatorId:req.user.id,inviteToken:token,memberRole:"owner",memberCount:1 } });
}
app.post("/api/groups", requireAuth, csrfCheck, (req,res)=>createChat(req,res,"group"));
app.post("/api/channels", requireAuth, csrfCheck, (req,res)=>createChat(req,res,"channel"));
app.post("/api/invites/:token/join", requireAuth, csrfCheck, (req,res)=>{
  const chat=db.prepare("SELECT * FROM chats WHERE invite_token=?").get(String(req.params.token));
  if(!chat) return res.status(404).json({error:"لینک دعوت نامعتبر است."});
  db.prepare("INSERT OR IGNORE INTO chat_members(chat_id,user_id,role) VALUES(?,?,'member')").run(chat.id,req.user.id);
  const result=chatForMember(chat.id,req.user.id);
  if(io.sockets.sockets) for(const s of io.sockets.sockets.values()) if(s.user?.id===req.user.id) s.join(`chat:${chat.id}`);
  res.json({chat:{id:result.id,name:result.name,description:result.description,type:result.type,creatorId:result.creator_id,inviteToken:result.invite_token,memberRole:result.memberRole}});
});
app.get("/api/chats/:id/messages", requireAuth, (req,res)=>{
  const id=Number(req.params.id); const chat=chatForMember(id,req.user.id);
  if(!chat) return res.status(403).json({error:"عضو این گروه/کانال نیستی."});
  const messages=db.prepare(`SELECT m.id,m.sender_id AS senderId,m.body,m.created_at AS createdAt,m.reply_to AS replyTo,m.edited_at AS editedAt,m.pinned,
    u.username AS senderUsername,u.display_name AS senderDisplayName,
    (SELECT json_group_array(json_object('emoji',r.emoji,'userId',r.user_id)) FROM reactions r WHERE r.message_id=m.id) AS reactions
    FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.chat_type=? AND m.chat_id=? ORDER BY m.id DESC LIMIT 300`).all(chat.type,id).reverse();
  res.json({messages:messages.map(m=>({...m,pinned:!!m.pinned,reactions:JSON.parse(m.reactions||"[]")}))});
});
app.post("/api/chats/:id/messages", requireAuth, csrfCheck, (req,res)=>{
  const id=Number(req.params.id); const chat=chatForMember(id,req.user.id); const body=String(req.body.body||"").trim();
  if(!chat) return res.status(403).json({error:"عضو این گروه/کانال نیستی."});
  if(chat.type==="channel" && !["owner","admin"].includes(chat.memberRole)) return res.status(403).json({error:"فقط مدیران کانال می‌توانند پیام بفرستند."});
  if(!body || body.length>4000) return res.status(400).json({error:"متن پیام نامعتبر است."});
  const replyTo=req.body.replyTo ? Number(req.body.replyTo) : null;
  if(replyTo && !db.prepare("SELECT id FROM messages WHERE id=? AND chat_type=? AND chat_id=?").get(replyTo,chat.type,id)) return res.status(400).json({error:"پیام برای پاسخ پیدا نشد."});
  const result=db.prepare("INSERT INTO messages(sender_id,recipient_id,body,chat_type,chat_id,reply_to) VALUES(?,?,?,?,?,?)").run(req.user.id,req.user.id,body,chat.type,id,replyTo);
  const m=db.prepare("SELECT m.id,m.sender_id AS senderId,m.body,m.created_at AS createdAt,m.reply_to AS replyTo,m.edited_at AS editedAt,m.pinned,u.username AS senderUsername,u.display_name AS senderDisplayName FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.id=?").get(result.lastInsertRowid);
  io.to(`chat:${id}`).emit("chat-message",{chatId:id,message:{...m,pinned:!!m.pinned,reactions:[]}});
  res.status(201).json({message:{...m,pinned:!!m.pinned,reactions:[]}});
});
function getChatMessage(id,userId){
 return db.prepare(`SELECT m.*,c.type AS ctype,c.id AS cid,cm.role AS memberRole FROM messages m
   LEFT JOIN chats c ON c.id=m.chat_id LEFT JOIN chat_members cm ON cm.chat_id=c.id AND cm.user_id=?
   WHERE m.id=? AND ((m.chat_type IN ('group','channel') AND cm.user_id IS NOT NULL) OR
   (m.chat_type='private' AND (m.sender_id=? OR m.recipient_id=?)))`).get(userId,id,userId,userId);
}
function emitMessageChange(m,event,payload){
 if(m.chat_type==='private'){io.to(`user:${m.sender_id}`).emit(event,payload);io.to(`user:${m.recipient_id}`).emit(event,payload)}
 else io.to(`chat:${m.chat_id}`).emit(event,{...payload,chatId:m.chat_id});
}
app.patch("/api/chat-messages/:id", requireAuth, csrfCheck, (req,res)=>{
 const id=Number(req.params.id),m=getChatMessage(id,req.user.id); if(!m)return res.status(404).json({error:"پیام پیدا نشد."});
 if(m.sender_id!==req.user.id && !["owner","admin"].includes(m.memberRole))return res.status(403).json({error:"فقط فرستنده یا مدیر می‌تواند پیام را ویرایش کند."});
 const body=String(req.body.body||"").trim(); if(!body||body.length>4000)return res.status(400).json({error:"متن نامعتبر است."});
 db.prepare("UPDATE messages SET body=?,edited_at=CURRENT_TIMESTAMP WHERE id=?").run(body,id);
 emitMessageChange(m,"message-updated",{id,body,editedAt:new Date().toISOString(),senderId:m.sender_id,recipientId:m.recipient_id}); res.json({ok:true});
});
app.delete("/api/chat-messages/:id", requireAuth, csrfCheck, (req,res)=>{
 const id=Number(req.params.id),m=getChatMessage(id,req.user.id); if(!m)return res.status(404).json({error:"پیام پیدا نشد."});
 if(m.sender_id!==req.user.id && !["owner","admin"].includes(m.memberRole))return res.status(403).json({error:"اجازهٔ حذف این پیام را نداری."});
 db.prepare("DELETE FROM messages WHERE id=?").run(id); emitMessageChange(m,"message-deleted",{id,senderId:m.sender_id,recipientId:m.recipient_id}); res.json({ok:true});
});
app.post("/api/chat-messages/:id/reactions", requireAuth, csrfCheck, (req,res)=>{
 const id=Number(req.params.id),m=getChatMessage(id,req.user.id),emoji=String(req.body.emoji||"");
 if(!m)return res.status(404).json({error:"پیام پیدا نشد."}); if(!/^(👍|❤️|😂|😮|😢|🔥|🎉|👎|😍)$/.test(emoji))return res.status(400).json({error:"واکنش پشتیبانی نمی‌شود."});
 const exists=db.prepare("SELECT 1 FROM reactions WHERE message_id=? AND user_id=? AND emoji=?").get(id,req.user.id,emoji);
 if(exists)db.prepare("DELETE FROM reactions WHERE message_id=? AND user_id=? AND emoji=?").run(id,req.user.id,emoji); else db.prepare("INSERT INTO reactions(message_id,user_id,emoji) VALUES(?,?,?)").run(id,req.user.id,emoji);
 const reactions=db.prepare("SELECT emoji,user_id AS userId FROM reactions WHERE message_id=?").all(id); emitMessageChange(m,"message-reactions",{id,reactions,senderId:m.sender_id,recipientId:m.recipient_id}); res.json({reactions});
});
app.post("/api/chat-messages/:id/pin", requireAuth, csrfCheck, (req,res)=>{
 const id=Number(req.params.id),m=getChatMessage(id,req.user.id); if(!m)return res.status(404).json({error:"پیام پیدا نشد."});
 if(m.chat_type!=="private" && !["owner","admin"].includes(m.memberRole))return res.status(403).json({error:"فقط مدیر گروه/کانال می‌تواند پیام را سنجاق کند."});
 const pinned=req.body.pinned!==false; db.prepare("UPDATE messages SET pinned=? WHERE id=?").run(pinned?1:0,id); emitMessageChange(m,"message-pinned",{id,pinned,senderId:m.sender_id,recipientId:m.recipient_id}); res.json({ok:true,pinned});
});

// Admin can create accounts, disable/enable them, and search stored messages.
app.get("/api/admin/users", requireAuth, requireAdmin, (req, res) => {
  res.json({ users: db.prepare("SELECT id,username,role,active,created_at AS createdAt FROM users ORDER BY id DESC").all() });
});
app.post("/api/admin/users", requireAuth, requireAdmin, csrfCheck, createLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");
  const role = req.body.role === "admin" ? "admin" : "user";
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) return res.status(400).json({ error: "نام کاربری باید ۳ تا ۳۲ نویسه و شامل حروف انگلیسی، عدد، نقطه، خط تیره یا زیرخط باشد." });
  if (password.length < 12 || password.length > 200) return res.status(400).json({ error: "رمز عبور باید دست‌کم ۱۲ نویسه باشد." });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users (username,password_hash,role) VALUES (?,?,?)").run(username, hash, role);
    res.status(201).json({ user: { id: Number(result.lastInsertRowid), username, role, active: true } });
  } catch (e) {
    if (String(e.code).includes("SQLITE_CONSTRAINT")) return res.status(409).json({ error: "این نام کاربری قبلاً استفاده شده است." });
    throw e;
  }
});
app.patch("/api/admin/users/:id", requireAuth, requireAdmin, csrfCheck, (req, res) => {
  const id = Number(req.params.id);
  const active = req.body.active;
  if (!Number.isSafeInteger(id) || id < 1 || typeof active !== "boolean") return res.status(400).json({ error: "درخواست نامعتبر است." });
  if (id === req.user.id && active === false) return res.status(400).json({ error: "نمی‌توانید حساب مدیر واردشده را غیرفعال کنید." });
  const result = db.prepare("UPDATE users SET active=? WHERE id=?").run(active ? 1 : 0, id);
  if (!result.changes) return res.status(404).json({ error: "کاربر پیدا نشد." });
  if (!active) {
    for (const s of io.sockets.sockets.values()) if (s.user && s.user.id === id) s.disconnect(true);
  }
  res.json({ ok: true });
});
app.get("/api/admin/messages", requireAuth, requireAdmin, (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 100);
  const rows = q
    ? db.prepare(`SELECT m.id,m.body,m.created_at AS createdAt,s.username AS senderUsername,r.username AS recipientUsername
       FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id
       WHERE m.body LIKE ? OR s.username LIKE ? OR r.username LIKE ?
       ORDER BY m.id DESC LIMIT 300`).all(`%${q}%`,`%${q}%`,`%${q}%`)
    : db.prepare(`SELECT m.id,m.body,m.created_at AS createdAt,s.username AS senderUsername,r.username AS recipientUsername
       FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id
       ORDER BY m.id DESC LIMIT 100`).all();
  res.json({ messages: rows });
});

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, () => {
    const user = currentUser(socket.request);
    if (!user || !user.active) return next(new Error("unauthorized"));
    socket.user = safeUser(user);
    next();
  });
});
io.on("connection", socket => {
  socket.join(`user:${socket.user.id}`);
  db.prepare("SELECT chat_id FROM chat_members WHERE user_id=?").all(socket.user.id).forEach(r => socket.join(`chat:${r.chat_id}`));
});

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "خطای داخلی سرور." });
});

server.listen(PORT, () => {
  console.log(`Friendly Geram is running at http://localhost:${PORT}`);
  if (production) console.log("Production mode: use HTTPS through a trusted reverse proxy.");
});
function shutdown() {
  server.close(() => { db.close(); process.exit(0); });
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
