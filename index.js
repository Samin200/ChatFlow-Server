// ============================================================
//  ChatFlow Backend - index.js
//  Single-file Node.js backend (Express + Socket.io + MongoDB)
// ============================================================

"use strict";

require("dotenv").config();

// --- ENV GUARD ------------------------------------------------
if (!process.env.JWT_SECRET) {
  console.error("[FATAL] Missing JWT_SECRET in environment. Set it in .env or as an env variable.");
  process.exit(1);
}

if (!process.env.MONGO_URL) {
  console.error("MONGO_URL missing");
  process.exit(1);
}

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");

// --- CONFIG ---------------------------------------------------
const PORT = process.env.PORT || 5020;
const MONGO_URL = process.env.MONGO_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";
const DB_NAME = "chatflow";
const SALT_ROUNDS = 10;
const TOKEN_TTL = "7d";

// --- APP SETUP ------------------------------------------------
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: CLIENT_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  },
});

app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: CLIENT_URL,
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// GET /sync/bootstrap - frontend startup (no auth)
app.get("/sync/bootstrap", (req, res) => {
  return res.json({ success: true, serverTime: Date.now() });
});

// --- MONGODB CONNECTION ---------------------------------------
let client;
let db;

async function connectDB() {
  try {
    client = new MongoClient(MONGO_URL);
    await client.connect();
    db = client.db("chatflow");
    console.log("MongoDB Connected");

    // -- Indexes --
    await db.collection("users").createIndex({ usernameLower: 1 }, { unique: true });
    await db.collection("chats").createIndex({ canonicalKey: 1 }, { sparse: true });
    await db.collection("messages").createIndex({ chatId: 1, createdAt: -1 });
    await db.collection("friends").createIndex({ userA: 1, userB: 1 }, { unique: true });

    console.log("[MongoDB] Indexes ensured.");
  } catch (err) {
    console.error("MongoDB Error:", err);
    process.exit(1);
  }
}

// --- HELPERS --------------------------------------------------

function newId() {
  return new ObjectId();
}

function toStr(id) {
  return id ? id.toString() : null;
}

function toObjectId(value) {
  if (!value) return null;
  const raw = String(value).trim();
  if (!ObjectId.isValid(raw)) return null;
  try {
    return new ObjectId(raw);
  } catch {
    return null;
  }
}

function escapeRegex(value) {
  return String(value || "").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sortedPairKey(a, b) {
  return [a, b].sort().join(":");
}

function ok(res, data = {}, status = 200) {
  return res.status(status).json({ success: true, ...data });
}

function fail(res, message = "Something went wrong", status = 400) {
  return res.status(status).json({ success: false, message });
}

function generateToken(userId) {
  return jwt.sign({ userId: toStr(userId) }, JWT_SECRET, { expiresIn: TOKEN_TTL });
}

function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

function safeUser(user) {
  if (!user) return null;
  const { passwordHash, usernameLower, ...rest } = user;
  return { ...rest, id: toStr(rest._id), _id: undefined };
}

function addOnlineSocket(userId, socketId) {
  const key = String(userId);
  const current = onlineUsers.get(key) || new Set();
  current.add(socketId);
  onlineUsers.set(key, current);
}

function removeOnlineSocket(userId, socketId) {
  const key = String(userId);
  const current = onlineUsers.get(key);
  if (!current) return;
  current.delete(socketId);
  if (!current.size) onlineUsers.delete(key);
}

function getOnlineSocketId(userId) {
  const key = String(userId);
  const current = onlineUsers.get(key);
  if (!current || !current.size) return null;
  const [sid] = current;
  return sid || null;
}

// --- AUTH MIDDLEWARE ------------------------------------------

async function requireAuth(req, res, next) {
  try {
    const header = req.headers["authorization"] || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : null;
    if (!token) return fail(res, "No token provided", 401);

    const payload = verifyToken(token);
    const userId = toObjectId(payload.userId);
    if (!userId) return fail(res, "Invalid token", 401);
    const user = await db.collection("users").findOne({ _id: userId });
    if (!user) return fail(res, "User not found", 401);

    req.user = user;
    next();
  } catch (err) {
    return fail(res, "Invalid or expired token", 401);
  }
}

// --- VALIDATION HELPERS ---------------------------------------

function validateUsername(username) {
  if (!username || typeof username !== "string") return "Username is required";
  if (username.length < 3 || username.length > 32) return "Username must be 3-32 characters";
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) return "Username may only contain letters, numbers, _, ., -";
  return null;
}

function validatePassword(password) {
  if (!password || typeof password !== "string") return "Password is required";
  if (password.length < 6) return "Password must be at least 6 characters";
  return null;
}

// ===============================================================
//  AUTH ROUTES
// ===============================================================

// POST /auth/register
app.post("/auth/register", async (req, res) => {
  try {
    let { username, displayName, password, avatarUrl } = req.body;

    const usernameErr = validateUsername(username);
    if (usernameErr) return fail(res, usernameErr);

    const passwordErr = validatePassword(password);
    if (passwordErr) return fail(res, passwordErr);

    const usernameLower = username.toLowerCase();
    displayName = displayName?.trim() || username;
    avatarUrl = avatarUrl || `https://api.dicebear.com/7.x/thumbs/svg?seed=${usernameLower}`;

    const existing = await db.collection("users").findOne({ usernameLower });
    if (existing) return fail(res, "Username already taken");

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const now = new Date();

    const insertResult = await db.collection("users").insertOne({
      username,
      usernameLower,
      displayName,
      passwordHash,
      avatarUrl,
      createdAt: now,
      lastSeenAt: now,
    });

    const userId = insertResult.insertedId;
    const token = generateToken(userId);

    return ok(
      res,
      {
        token,
        user: {
          id: toStr(userId),
          username,
          displayName,
          avatarUrl,
          createdAt: now,
          lastSeenAt: now,
        },
      },
      201
    );
  } catch (err) {
    if (err.code === 11000) return fail(res, "Username already taken");
    console.error("[register]", err);
    return fail(res, "Registration failed", 500);
  }
});

// POST /auth/login
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) return fail(res, "Username and password required");

    const user = await db.collection("users").findOne({ usernameLower: username.toLowerCase() });
    if (!user) return fail(res, "Invalid credentials", 401);

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return fail(res, "Invalid credentials", 401);

    await db.collection("users").updateOne({ _id: user._id }, { $set: { lastSeenAt: new Date() } });

    const token = generateToken(user._id);
    return ok(res, { token, user: safeUser(user) });
  } catch (err) {
    console.error("[login]", err);
    return fail(res, "Login failed", 500);
  }
});

// GET /auth/me
app.get("/auth/me", requireAuth, (req, res) => {
  return ok(res, { user: safeUser(req.user) });
});

// PATCH /auth/me  -- update profile
app.patch("/auth/me", requireAuth, async (req, res) => {
  try {
    const { displayName, avatarUrl } = req.body;
    const updates = {};
    if (displayName) updates.displayName = displayName.trim();
    if (avatarUrl) updates.avatarUrl = avatarUrl.trim();

    if (!Object.keys(updates).length) return fail(res, "Nothing to update");

    await db.collection("users").updateOne({ _id: req.user._id }, { $set: updates });
    const updated = await db.collection("users").findOne({ _id: req.user._id });
    return ok(res, { user: safeUser(updated) });
  } catch (err) {
    console.error("[update profile]", err);
    return fail(res, "Profile update failed", 500);
  }
});

// ===============================================================
//  USER ROUTES
// ===============================================================

// GET /users/search?q=username
app.get("/users/search", requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || "").toLowerCase().trim();
    if (!q || q.length < 2) return fail(res, "Query too short");
    const safe = escapeRegex(q);

    const users = await db
      .collection("users")
      .find({ usernameLower: { $regex: `^${safe}`, $options: "i" } })
      .limit(20)
      .toArray();

    return ok(res, { users: users.map(safeUser) });
  } catch (err) {
    console.error("[search users]", err);
    return fail(res, "Search failed", 500);
  }
});

// GET /users/:id
app.get("/users/:id", requireAuth, async (req, res) => {
  try {
    const userId = toObjectId(req.params.id);
    if (!userId) return fail(res, "User not found", 404);
    const user = await db.collection("users").findOne({ _id: userId });
    if (!user) return fail(res, "User not found", 404);
    return ok(res, { user: safeUser(user) });
  } catch (err) {
    return fail(res, "User not found", 404);
  }
});

// ===============================================================
//  FRIEND SYSTEM
// ===============================================================
//
//  friends collection document:
//  {
//    userA, userB,          // always sorted so userA < userB (string comparison)
//    canonicalKey,          // "userA:userB"
//    status,                // "pending" | "friends" | "blocked"
//    requestedBy,           // userId who sent the request
//    blockedBy,             // userId who blocked (if blocked)
//    createdAt, updatedAt
//  }

function sortedPair(idA, idB) {
  const [a, b] = [toStr(idA), toStr(idB)].sort();
  return { userA: a, userB: b, canonicalKey: `${a}:${b}` };
}

async function getFriendStatus(meId, otherId) {
  const { canonicalKey } = sortedPair(meId, otherId);
  const doc = await db.collection("friends").findOne({ canonicalKey });
  if (!doc) return { status: "none", doc: null };

  const meStr = toStr(meId);
  const otherStr = toStr(otherId);

  if (doc.status === "blocked") {
    if (doc.blockedBy === meStr) return { status: "blocked_by_me", doc };
    return { status: "blocked_by_them", doc };
  }
  if (doc.status === "pending") {
    if (doc.requestedBy === meStr) return { status: "outgoing", doc };
    return { status: "incoming", doc };
  }
  if (doc.status === "friends") return { status: "friends", doc };
  return { status: "none", doc };
}

// POST /friends/request
app.post("/friends/request", requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");
    if (toStr(req.user._id) === toStr(userId)) return fail(res, "Cannot friend yourself");

    const targetId = toObjectId(userId);
    if (!targetId) return fail(res, "User not found", 404);
    const target = await db.collection("users").findOne({ _id: targetId });
    if (!target) return fail(res, "User not found", 404);

    const pair = sortedPair(req.user._id, userId);
    const existing = await db.collection("friends").findOne({ canonicalKey: pair.canonicalKey });

    if (existing) {
      if (existing.status === "friends") return fail(res, "Already friends");
      if (existing.status === "pending") return fail(res, "Request already exists");
      if (existing.status === "blocked") return fail(res, "Cannot send request");
    }

    const now = new Date();
    await db.collection("friends").insertOne({
      ...pair,
      status: "pending",
      requestedBy: toStr(req.user._id),
      blockedBy: null,
      createdAt: now,
      updatedAt: now,
    });

    // real-time notify target
    const targetSocketId = getOnlineSocketId(toStr(userId));
    if (targetSocketId) {
      io.to(targetSocketId).emit("friend:request", {
        from: safeUser(req.user),
      });
    }

    return ok(res, { message: "Friend request sent" }, 201);
  } catch (err) {
    console.error("[friend request]", err);
    return fail(res, "Failed to send request", 500);
  }
});

// POST /friends/accept
app.post("/friends/accept", requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");

    const pair = sortedPair(req.user._id, userId);
    const doc = await db.collection("friends").findOne({ canonicalKey: pair.canonicalKey });

    if (!doc || doc.status !== "pending") return fail(res, "No pending request found");
    if (doc.requestedBy === toStr(req.user._id)) return fail(res, "Cannot accept your own request");

    await db.collection("friends").updateOne(
      { canonicalKey: pair.canonicalKey },
      { $set: { status: "friends", updatedAt: new Date() } }
    );

    const targetSocketId = getOnlineSocketId(toStr(userId));
    if (targetSocketId) {
      io.to(targetSocketId).emit("friend:accepted", { by: safeUser(req.user) });
    }

    return ok(res, { message: "Friend request accepted" });
  } catch (err) {
    console.error("[friend accept]", err);
    return fail(res, "Failed to accept request", 500);
  }
});

// POST /friends/reject
app.post("/friends/reject", requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");

    const pair = sortedPair(req.user._id, userId);
    await db.collection("friends").deleteOne({ canonicalKey: pair.canonicalKey, status: "pending" });

    return ok(res, { message: "Friend request rejected" });
  } catch (err) {
    console.error("[friend reject]", err);
    return fail(res, "Failed to reject request", 500);
  }
});

// POST /friends/block
app.post("/friends/block", requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");

    const pair = sortedPair(req.user._id, userId);
    const meStr = toStr(req.user._id);
    const now = new Date();

    await db.collection("friends").updateOne(
      { canonicalKey: pair.canonicalKey },
      {
        $set: {
          ...pair,
          status: "blocked",
          blockedBy: meStr,
          updatedAt: now,
        },
        $setOnInsert: { requestedBy: null, createdAt: now },
      },
      { upsert: true }
    );

    return ok(res, { message: "User blocked" });
  } catch (err) {
    console.error("[block]", err);
    return fail(res, "Failed to block user", 500);
  }
});

// POST /friends/unblock
app.post("/friends/unblock", requireAuth, async (req, res) => {
  try {
    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");

    const pair = sortedPair(req.user._id, userId);
    const doc = await db.collection("friends").findOne({ canonicalKey: pair.canonicalKey });

    if (!doc || doc.status !== "blocked") return fail(res, "User is not blocked");
    if (doc.blockedBy !== toStr(req.user._id)) return fail(res, "You did not block this user");

    await db.collection("friends").deleteOne({ canonicalKey: pair.canonicalKey });
    return ok(res, { message: "User unblocked" });
  } catch (err) {
    console.error("[unblock]", err);
    return fail(res, "Failed to unblock user", 500);
  }
});

// GET /friends  -- list all friends of current user
app.get("/friends", requireAuth, async (req, res) => {
  try {
    const meStr = toStr(req.user._id);
    const docs = await db
      .collection("friends")
      .find({
        $or: [{ userA: meStr }, { userB: meStr }],
        status: "friends",
      })
      .toArray();

    const friendIds = docs.map((d) => {
      const otherId = d.userA === meStr ? d.userB : d.userA;
      return toObjectId(otherId);
    }).filter(Boolean);

    if (!friendIds.length) return ok(res, { friends: [] });

    const users = await db
      .collection("users")
      .find({ _id: { $in: friendIds } })
      .toArray();

    return ok(res, { friends: users.map(safeUser) });
  } catch (err) {
    console.error("[list friends]", err);
    return fail(res, "Failed to list friends", 500);
  }
});

// GET /friends/requests  -- incoming + outgoing
app.get("/friends/requests", requireAuth, async (req, res) => {
  try {
    const meStr = toStr(req.user._id);
    const docs = await db
      .collection("friends")
      .find({
        $or: [{ userA: meStr }, { userB: meStr }],
        status: "pending",
      })
      .toArray();

    const incoming = [];
    const outgoing = [];
    const otherIds = docs
      .map((d) => (d.userA === meStr ? d.userB : d.userA))
      .map(toObjectId)
      .filter(Boolean);
    const users = otherIds.length
      ? await db.collection("users").find({ _id: { $in: otherIds } }).toArray()
      : [];
    const userById = new Map(users.map((u) => [toStr(u._id), safeUser(u)]));

    docs.forEach((d) => {
      const otherId = d.userA === meStr ? d.userB : d.userA;
      const user = userById.get(String(otherId));
      if (!user) return;
      if (d.requestedBy === meStr) outgoing.push(user);
      else incoming.push(user);
    });

    return ok(res, { incoming, outgoing });
  } catch (err) {
    console.error("[friend requests]", err);
    return fail(res, "Failed to fetch requests", 500);
  }
});

// GET /friends/status/:userId
app.get("/friends/status/:userId", requireAuth, async (req, res) => {
  try {
    const { status } = await getFriendStatus(req.user._id, req.params.userId);
    return ok(res, { status });
  } catch (err) {
    return fail(res, "Failed to get status", 500);
  }
});

// ===============================================================
//  CHAT ROUTES
// ===============================================================
//
//  Chat document:
//  {
//    _id, type ("dm" | "group"),
//    canonicalKey (DM only),
//    name (group only),
//    avatarUrl (group only),
//    members: [userId strings],
//    ownerId (group only),
//    admins: [] (group only),
//    createdAt, updatedAt,
//    lastMessage: { content, senderId, createdAt }
//  }

// POST /chats/create
app.post("/chats/create", requireAuth, async (req, res) => {
  try {
    const { type, userId, name, avatarUrl, members } = req.body;
    const meStr = toStr(req.user._id);
    const now = new Date();

    // -- DM --
    if (type === "dm") {
      if (!userId) return fail(res, "userId required for DM");
      if (userId === meStr) return fail(res, "Cannot DM yourself");

      const targetId = toObjectId(userId);
      if (!targetId) return fail(res, "User not found", 404);
      const target = await db.collection("users").findOne({ _id: targetId });
      if (!target) return fail(res, "User not found", 404);

      const canonicalKey = sortedPairKey(meStr, userId);
      const existing = await db.collection("chats").findOne({ canonicalKey });
      if (existing) return ok(res, { chat: { ...existing, id: toStr(existing._id) } });

      const insertResult = await db.collection("chats").insertOne({
        type: "dm",
        canonicalKey,
        members: [meStr, userId],
        createdAt: now,
        updatedAt: now,
        lastMessage: null,
      });

      const chat = await db.collection("chats").findOne({ _id: insertResult.insertedId });
      return ok(res, { chat: { ...chat, id: toStr(chat._id) } }, 201);
    }

    // -- GROUP --
    if (type === "group") {
      if (!name || !name.trim()) return fail(res, "Group name required");

      const memberIds = Array.isArray(members) ? [...new Set([meStr, ...members])] : [meStr];

      const insertResult = await db.collection("chats").insertOne({
        type: "group",
        name: name.trim(),
        avatarUrl: avatarUrl || `https://api.dicebear.com/7.x/identicon/svg?seed=${Date.now()}`,
        members: memberIds,
        ownerId: meStr,
        admins: [meStr],
        createdAt: now,
        updatedAt: now,
        lastMessage: null,
      });

      const chat = await db.collection("chats").findOne({ _id: insertResult.insertedId });
      return ok(res, { chat: { ...chat, id: toStr(chat._id) } }, 201);
    }

    return fail(res, "type must be 'dm' or 'group'");
  } catch (err) {
    console.error("[create chat]", err);
    return fail(res, "Failed to create chat", 500);
  }
});

// GET /chats/:id
app.get("/chats/:id", requireAuth, async (req, res) => {
  try {
    const chatId = toObjectId(req.params.id);
    if (!chatId) return fail(res, "Chat not found", 404);
    const chat = await db.collection("chats").findOne({ _id: chatId });
    if (!chat) return fail(res, "Chat not found", 404);

    const meStr = toStr(req.user._id);
    if (!chat.members.includes(meStr)) return fail(res, "Not a member", 403);

    return ok(res, { chat: { ...chat, id: toStr(chat._id) } });
  } catch (err) {
    return fail(res, "Chat not found", 404);
  }
});

// GET /chats  -- list my chats
app.get("/chats", requireAuth, async (req, res) => {
  try {
    const meStr = toStr(req.user._id);
    const chats = await db.collection("chats").find({ members: meStr }).sort({ updatedAt: -1 }).toArray();

    return ok(res, { chats: chats.map((c) => ({ ...c, id: toStr(c._id) })) });
  } catch (err) {
    console.error("[list chats]", err);
    return fail(res, "Failed to list chats", 500);
  }
});

// PATCH /chats/:id  -- rename group, change avatar
app.patch("/chats/:id", requireAuth, async (req, res) => {
  try {
    const chatId = toObjectId(req.params.id);
    if (!chatId) return fail(res, "Chat not found", 404);
    const chat = await db.collection("chats").findOne({ _id: chatId });
    if (!chat) return fail(res, "Chat not found", 404);
    if (chat.type !== "group") return fail(res, "Only group chats can be updated");

    const meStr = toStr(req.user._id);
    if (!chat.admins.includes(meStr)) return fail(res, "Admin only", 403);

    const { name, avatarUrl } = req.body;
    const updates = { updatedAt: new Date() };
    if (name) updates.name = name.trim();
    if (avatarUrl) updates.avatarUrl = avatarUrl;

    await db.collection("chats").updateOne({ _id: chat._id }, { $set: updates });
    const updated = await db.collection("chats").findOne({ _id: chat._id });
    return ok(res, { chat: { ...updated, id: toStr(updated._id) } });
  } catch (err) {
    console.error("[update chat]", err);
    return fail(res, "Failed to update chat", 500);
  }
});

// POST /chats/:id/members  -- add member (admin only)
app.post("/chats/:id/members", requireAuth, async (req, res) => {
  try {
    const chatId = toObjectId(req.params.id);
    if (!chatId) return fail(res, "Chat not found", 404);
    const chat = await db.collection("chats").findOne({ _id: chatId });
    if (!chat) return fail(res, "Chat not found", 404);
    if (chat.type !== "group") return fail(res, "Only for groups");

    const meStr = toStr(req.user._id);
    if (!chat.admins.includes(meStr)) return fail(res, "Admin only", 403);

    const { userId } = req.body;
    if (!userId) return fail(res, "userId required");
    if (chat.members.includes(userId)) return fail(res, "Already a member");

    await db.collection("chats").updateOne(
      { _id: chat._id },
      { $push: { members: userId }, $set: { updatedAt: new Date() } }
    );

    return ok(res, { message: "Member added" });
  } catch (err) {
    return fail(res, "Failed to add member", 500);
  }
});

// DELETE /chats/:id/members/:userId  -- remove member
app.delete("/chats/:id/members/:userId", requireAuth, async (req, res) => {
  try {
    const chatId = toObjectId(req.params.id);
    if (!chatId) return fail(res, "Chat not found", 404);
    const chat = await db.collection("chats").findOne({ _id: chatId });
    if (!chat) return fail(res, "Chat not found", 404);
    if (chat.type !== "group") return fail(res, "Only for groups");

    const meStr = toStr(req.user._id);
    const targetStr = req.params.userId;

    // must be admin OR removing yourself (leave)
    if (!chat.admins.includes(meStr) && meStr !== targetStr) {
      return fail(res, "Admin only", 403);
    }

    await db.collection("chats").updateOne(
      { _id: chat._id },
      { $pull: { members: targetStr, admins: targetStr }, $set: { updatedAt: new Date() } }
    );

    return ok(res, { message: "Member removed" });
  } catch (err) {
    return fail(res, "Failed to remove member", 500);
  }
});

// ===============================================================
//  MESSAGE ROUTES
// ===============================================================

// -- Mention parser --
async function parseMentions(content, chatMembers) {
  const mentionedUserIds = [];
  let hasEveryone = false;
  let hasHere = false;

  if (/@everyone/.test(content)) hasEveryone = true;
  if (/@here/.test(content)) hasHere = true;

  const matches = [...content.matchAll(/@([a-zA-Z0-9_.-]+)/g)];
  for (const [, uname] of matches) {
    if (uname === "everyone" || uname === "here") continue;
    const user = await db.collection("users").findOne({ usernameLower: uname.toLowerCase() });
    if (user && chatMembers.includes(toStr(user._id))) {
      if (!mentionedUserIds.includes(toStr(user._id))) {
        mentionedUserIds.push(toStr(user._id));
      }
    }
  }

  return { mentionedUserIds, hasEveryone, hasHere };
}

// POST /messages/send
app.post("/messages/send", requireAuth, async (req, res) => {
  try {
    const { chatId, content, attachments, replyToId } = req.body;
    if (!chatId) return fail(res, "chatId required");
    if (!content && (!attachments || !attachments.length)) {
      return fail(res, "Message cannot be empty");
    }

    const chatObjectId = toObjectId(chatId);
    if (!chatObjectId) return fail(res, "Chat not found", 404);
    const chat = await db.collection("chats").findOne({ _id: chatObjectId });
    if (!chat) return fail(res, "Chat not found", 404);

    const meStr = toStr(req.user._id);
    if (!chat.members.includes(meStr)) return fail(res, "Not a member", 403);

    const messageContent = (content || "").trim();
    const { mentionedUserIds, hasEveryone, hasHere } = await parseMentions(messageContent, chat.members);

    const now = new Date();
    const message = {
      chatId: chatId,
      senderId: meStr,
      content: messageContent,
      attachments: Array.isArray(attachments) ? attachments : [],
      reactions: {},
      mentionedUserIds,
      hasEveryone,
      hasHere,
      replyToId: replyToId || null,
      createdAt: now,
      editedAt: null,
      deletedAt: null,
    };

    const insertResult = await db.collection("messages").insertOne(message);
    const savedMsg = { ...message, id: toStr(insertResult.insertedId), _id: insertResult.insertedId };

    // update chat lastMessage
    await db.collection("chats").updateOne(
      { _id: chat._id },
      {
        $set: {
          updatedAt: now,
          lastMessage: { content: messageContent, senderId: meStr, createdAt: now },
        },
      }
    );

    // broadcast to chat room
    io.to(chatId).emit("message:new", { ...savedMsg, _id: undefined, id: toStr(insertResult.insertedId) });

    // notify mentioned users
    for (const uid of mentionedUserIds) {
      const socketId = onlineUsers.get(uid);
      if (socketId) {
        io.to(socketId).emit("mention:received", {
          chatId,
          messageId: toStr(insertResult.insertedId),
          from: safeUser(req.user),
        });
      }
    }

    return ok(res, { message: { ...savedMsg, _id: undefined } }, 201);
  } catch (err) {
    console.error("[send message]", err);
    return fail(res, "Failed to send message", 500);
  }
});

// GET /messages/:chatId -- chatId is always a string (e.g. "study-general", "userA:userB")
app.get("/messages/:chatId", requireAuth, async (req, res) => {
  try {
    const chatId = String(req.params.chatId ?? "");
    const meStr = toStr(req.user._id);
    console.log("[messages] fetch chatId=%s user=%s", chatId, meStr);

    // Safe membership: resolve chat by canonicalKey or valid ObjectId string only (never throw on invalid id)
    let chat = null;
    try {
      if (chatId.length === 24 && ObjectId.isValid(chatId)) {
        chat = await db.collection("chats").findOne({ _id: new ObjectId(chatId) });
      }
    } catch (lookupErr) {
      console.error("[messages] chat lookup by _id error", lookupErr);
    }
    if (!chat) {
      try {
        chat = await db.collection("chats").findOne({ canonicalKey: chatId });
      } catch (lookupErr) {
        console.error("[messages] chat lookup by canonicalKey error", lookupErr);
      }
    }
    if (chat && Array.isArray(chat.members) && !chat.members.includes(meStr)) {
      return fail(res, "Not a member", 403);
    }

    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const before = req.query.before;
    const query = { chatId, deletedAt: null };
    if (before) {
      try {
        query.createdAt = { $lt: new Date(before) };
      } catch (dateErr) {
        console.error("[messages] invalid before cursor", dateErr);
      }
    }

    const messages = await db.collection("messages").find(query).sort({ createdAt: 1 }).limit(limit).toArray();

    const result = messages.map((m) => ({ ...m, id: toStr(m._id), _id: undefined }));
    return ok(res, { messages: result });
  } catch (err) {
    console.error("[get messages] error (returning 500, server stays up)", err);
    return res.status(500).json({ success: false, message: "Failed to get messages" });
  }
});

// PATCH /messages/:id  -- edit message
app.patch("/messages/:id", requireAuth, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || !content.trim()) return fail(res, "Content required");

    const messageId = toObjectId(req.params.id);
    if (!messageId) return fail(res, "Message not found", 404);
    const msg = await db.collection("messages").findOne({ _id: messageId });
    if (!msg) return fail(res, "Message not found", 404);
    if (msg.senderId !== toStr(req.user._id)) return fail(res, "Cannot edit others' messages", 403);
    if (msg.deletedAt) return fail(res, "Cannot edit deleted message");

    const now = new Date();
    await db.collection("messages").updateOne({ _id: msg._id }, { $set: { content: content.trim(), editedAt: now } });

    const updated = await db.collection("messages").findOne({ _id: msg._id });
    const result = { ...updated, id: toStr(updated._id), _id: undefined };

    io.to(msg.chatId).emit("message:update", result);
    return ok(res, { message: result });
  } catch (err) {
    console.error("[edit message]", err);
    return fail(res, "Failed to edit message", 500);
  }
});

// DELETE /messages/:id  -- soft delete
app.delete("/messages/:id", requireAuth, async (req, res) => {
  try {
    const messageId = toObjectId(req.params.id);
    if (!messageId) return fail(res, "Message not found", 404);
    const msg = await db.collection("messages").findOne({ _id: messageId });
    if (!msg) return fail(res, "Message not found", 404);

    const meStr = toStr(req.user._id);

    // sender or group admin can delete
    const chatObjectId = toObjectId(msg.chatId);
    const chat = chatObjectId ? await db.collection("chats").findOne({ _id: chatObjectId }) : null;
    const isAdmin = chat?.type === "group" && chat?.admins?.includes(meStr);
    const isSender = msg.senderId === meStr;

    if (!isSender && !isAdmin) return fail(res, "Cannot delete this message", 403);

    await db.collection("messages").updateOne(
      { _id: msg._id },
      { $set: { deletedAt: new Date(), content: "This message was deleted." } }
    );

    io.to(msg.chatId).emit("message:delete", { id: toStr(msg._id), chatId: msg.chatId });
    return ok(res, { message: "Message deleted" });
  } catch (err) {
    console.error("[delete message]", err);
    return fail(res, "Failed to delete message", 500);
  }
});

// ===============================================================
//  REACTION SYSTEM
// ===============================================================

// POST /messages/react
app.post("/messages/react", requireAuth, async (req, res) => {
  try {
    const { messageId, emoji } = req.body;
    if (!messageId || !emoji) return fail(res, "messageId and emoji required");

    const messageObjectId = toObjectId(messageId);
    if (!messageObjectId) return fail(res, "Message not found", 404);
    const msg = await db.collection("messages").findOne({ _id: messageObjectId });
    if (!msg) return fail(res, "Message not found", 404);
    if (msg.deletedAt) return fail(res, "Cannot react to deleted message");

    // verify membership
    const chatObjectId = toObjectId(msg.chatId);
    const chat = chatObjectId ? await db.collection("chats").findOne({ _id: chatObjectId }) : null;
    const meStr = toStr(req.user._id);
    if (!chat || !chat.members.includes(meStr)) return fail(res, "Not a member", 403);

    const reactions = msg.reactions || {};

    // find if user already reacted with any emoji
    let existingEmoji = null;
    for (const [e, data] of Object.entries(reactions)) {
      if (data.users && data.users.includes(meStr)) {
        existingEmoji = e;
        break;
      }
    }

    if (existingEmoji === emoji) {
      // same emoji -> REMOVE reaction
      reactions[emoji].users = reactions[emoji].users.filter((u) => u !== meStr);
      if (reactions[emoji].users.length === 0) delete reactions[emoji];
    } else {
      // remove from old emoji if any
      if (existingEmoji) {
        reactions[existingEmoji].users = reactions[existingEmoji].users.filter((u) => u !== meStr);
        if (reactions[existingEmoji].users.length === 0) delete reactions[existingEmoji];
      }
      // add to new emoji
      if (!reactions[emoji]) reactions[emoji] = { users: [] };
      reactions[emoji].users.push(meStr);
    }

    await db.collection("messages").updateOne({ _id: msg._id }, { $set: { reactions } });

    const reactionUpdate = { messageId, chatId: msg.chatId, reactions };
    io.to(msg.chatId).emit("reaction:update", reactionUpdate);
    return ok(res, { reactions });
  } catch (err) {
    console.error("[react]", err);
    return fail(res, "Failed to react", 500);
  }
});

// ===============================================================
//  SOCKET.IO - REAL-TIME ENGINE
// ===============================================================

// Map: userId -> Set<socketId>  (online users)
const onlineUsers = new Map();

io.use(async (socket, next) => {
  try {
    // Token MUST come from handshake auth (matches Socket.IO client: io(url, { auth: { token } }))
    const raw = socket.handshake.auth && socket.handshake.auth.token;
    if (raw === undefined || raw === null || String(raw).trim() === "") {
      console.warn("[Socket] connect rejected: missing auth.token");
      return next(new Error("No token"));
    }

    let cleanToken = String(raw).trim();
    if (cleanToken.startsWith("Bearer ")) cleanToken = cleanToken.slice(7).trim();

    let decodedUser;
    try {
      decodedUser = verifyToken(cleanToken);
    } catch (verifyErr) {
      console.error("[Socket] JWT verify failed", verifyErr);
      return next(new Error("Authentication failed"));
    }

    let user;
    try {
      const socketUserId = toObjectId(decodedUser.userId);
      if (!socketUserId) return next(new Error("Authentication failed"));
      user = await db.collection("users").findOne({ _id: socketUserId });
    } catch (dbErr) {
      console.error("[Socket] user load failed", dbErr);
      return next(new Error("Authentication failed"));
    }
    if (!user) {
      console.warn("[Socket] connect rejected: user not found for token");
      return next(new Error("User not found"));
    }

    socket.user = decodedUser;
    socket.userId = toStr(user._id);
    socket.userData = user;
    next();
  } catch (err) {
    console.error("[Socket] auth middleware unexpected error", err);
    return next(new Error("Authentication failed"));
  }
});

io.on("connection", async (socket) => {
  const userId = socket.userId;
  const uname = socket.userData && socket.userData.username;
  console.log(`[Socket] Connected: ${uname || userId} (socket ${socket.id})`);

  try {
    // register as online
    addOnlineSocket(userId, socket.id);

    // update lastSeenAt
    const socketUserId = toObjectId(userId);
    if (socketUserId) {
      await db.collection("users").updateOne({ _id: socketUserId }, { $set: { lastSeenAt: new Date() } });
    }

    // broadcast online status to friends
    await broadcastOnlineStatus(socket, userId, true);

    // auto-join all chat rooms user belongs to
    const userChats = await db.collection("chats").find({ members: userId }).toArray();
    for (const chat of userChats) {
      socket.join(toStr(chat._id));
    }
    console.log(`[Socket] ${uname || userId} joined ${userChats.length} chat room(s)`);
  } catch (setupErr) {
    console.error("[Socket] post-connect setup failed (socket stays connected)", setupErr);
  }

  // -- join:chat -- (explicit join for newly created chats)
  socket.on("join:chat", async (chatId) => {
    const chatObjectId = toObjectId(chatId);
    if (!chatObjectId) return;
    try {
      const chat = await db.collection("chats").findOne({ _id: chatObjectId }, { projection: { members: 1 } });
      if (!chat || !Array.isArray(chat.members) || !chat.members.includes(userId)) return;
      const roomId = toStr(chatObjectId);
      socket.join(roomId);
      console.log(`[Socket] ${uname || userId} joined room ${roomId}`);
    } catch {
      // noop
    }
  });

  // -- leave:chat --
  socket.on("leave:chat", (chatId) => {
    const chatObjectId = toObjectId(chatId);
    if (!chatObjectId) return;
    socket.leave(toStr(chatObjectId));
  });

  // -- typing:start --
  socket.on("typing:start", async ({ chatId }) => {
    const chatObjectId = toObjectId(chatId);
    if (!chatObjectId) return;
    try {
      const chat = await db.collection("chats").findOne({ _id: chatObjectId }, { projection: { members: 1 } });
      if (!chat || !Array.isArray(chat.members) || !chat.members.includes(userId)) return;
      const roomId = toStr(chatObjectId);
      socket.to(roomId).emit("typing:start", {
        chatId: roomId,
        userId,
        username: socket.userData && socket.userData.username,
        displayName: socket.userData && socket.userData.displayName,
      });
    } catch {
      // noop
    }
  });

  // -- typing:stop --
  socket.on("typing:stop", async ({ chatId }) => {
    const chatObjectId = toObjectId(chatId);
    if (!chatObjectId) return;
    try {
      const chat = await db.collection("chats").findOne({ _id: chatObjectId }, { projection: { members: 1 } });
      if (!chat || !Array.isArray(chat.members) || !chat.members.includes(userId)) return;
      const roomId = toStr(chatObjectId);
      socket.to(roomId).emit("typing:stop", {
        chatId: roomId,
        userId,
      });
    } catch {
      // noop
    }
  });

  // -- message:send via socket (alternative to REST) --
  socket.on("message:send", async (data, ack) => {
    try {
      const { chatId, content, attachments, replyToId } = data;
      if (!chatId || (!content && (!attachments || !attachments.length))) {
        if (ack) ack({ error: "chatId and content required" });
        return;
      }

      const chatObjectId = toObjectId(chatId);
      if (!chatObjectId) {
        if (ack) ack({ error: "Chat not found or not a member" });
        return;
      }
      const chat = await db.collection("chats").findOne({ _id: chatObjectId });
      if (!chat || !chat.members.includes(userId)) {
        if (ack) ack({ error: "Chat not found or not a member" });
        return;
      }

      const roomId = toStr(chatObjectId);

      const messageContent = (content || "").trim();
      const { mentionedUserIds, hasEveryone, hasHere } = await parseMentions(messageContent, chat.members);

      const now = new Date();
      const message = {
        chatId: roomId,
        senderId: userId,
        content: messageContent,
        attachments: Array.isArray(attachments) ? attachments : [],
        reactions: {},
        mentionedUserIds,
        hasEveryone,
        hasHere,
        replyToId: replyToId || null,
        createdAt: now,
        editedAt: null,
        deletedAt: null,
      };

      const result = await db.collection("messages").insertOne(message);
      const saved = { ...message, id: toStr(result.insertedId), _id: undefined };

      await db.collection("chats").updateOne(
        { _id: chat._id },
        { $set: { updatedAt: now, lastMessage: { content: messageContent, senderId: userId, createdAt: now } } }
      );

      io.to(roomId).emit("message:new", saved);

      for (const uid of mentionedUserIds) {
        const sid = getOnlineSocketId(uid);
        if (sid) io.to(sid).emit("mention:received", { chatId, messageId: toStr(result.insertedId) });
      }

      if (ack) ack({ success: true, message: saved });
    } catch (err) {
      console.error("[socket message:send]", err);
      if (ack) ack({ error: "Failed to send message" });
    }
  });

  // -- message:react via socket --
  socket.on("message:react", async (data, ack) => {
    try {
      const { messageId, emoji } = data;
      if (!messageId || !emoji) {
        if (ack) ack({ error: "messageId and emoji required" });
        return;
      }

      const messageObjectId = toObjectId(messageId);
      if (!messageObjectId) {
        if (ack) ack({ error: "Message not found" });
        return;
      }
      const msg = await db.collection("messages").findOne({ _id: messageObjectId });
      if (!msg || msg.deletedAt) {
        if (ack) ack({ error: "Message not found" });
        return;
      }

      const reactions = msg.reactions || {};
      let existingEmoji = null;
      for (const [e, d] of Object.entries(reactions)) {
        if (d.users && d.users.includes(userId)) {
          existingEmoji = e;
          break;
        }
      }

      if (existingEmoji === emoji) {
        reactions[emoji].users = reactions[emoji].users.filter((u) => u !== userId);
        if (reactions[emoji].users.length === 0) delete reactions[emoji];
      } else {
        if (existingEmoji) {
          reactions[existingEmoji].users = reactions[existingEmoji].users.filter((u) => u !== userId);
          if (reactions[existingEmoji].users.length === 0) delete reactions[existingEmoji];
        }
        if (!reactions[emoji]) reactions[emoji] = { users: [] };
        reactions[emoji].users.push(userId);
      }

      await db.collection("messages").updateOne({ _id: msg._id }, { $set: { reactions } });
      io.to(msg.chatId).emit("reaction:update", { messageId, chatId: msg.chatId, reactions });
      if (ack) ack({ success: true, reactions });
    } catch (err) {
      console.error("[socket react]", err);
      if (ack) ack({ error: "Failed to react" });
    }
  });

  // -- disconnect --
  socket.on("disconnect", async (reason) => {
    const dname = socket.userData && socket.userData.username;
    console.log(`[Socket] Disconnected: ${dname || userId} (socket ${socket.id}) reason=%s`, reason);
    removeOnlineSocket(userId, socket.id);

    try {
      const socketUserId = toObjectId(userId);
      if (socketUserId) {
        await db.collection("users").updateOne({ _id: socketUserId }, { $set: { lastSeenAt: new Date() } });
      }
    } catch (e) {
      console.error("[Socket] disconnect lastSeen update failed", e);
    }

    try {
      await broadcastOnlineStatus(socket, userId, false);
    } catch (e) {
      console.error("[Socket] disconnect broadcast failed", e);
    }
  });
});

// Helper: broadcast online/offline to mutual friends
async function broadcastOnlineStatus(socket, userId, isOnline) {
  try {
    const docs = await db
      .collection("friends")
      .find({
        $or: [{ userA: userId }, { userB: userId }],
        status: "friends",
      })
      .toArray();

    for (const d of docs) {
      const friendId = d.userA === userId ? d.userB : d.userA;
      const friendSid = getOnlineSocketId(friendId);
      if (friendSid) {
        io.to(friendSid).emit(isOnline ? "user:online" : "user:offline", { userId });
      }
    }
  } catch (_) {
    // silent
  }
}

// ===============================================================
//  HEALTH CHECK
// ===============================================================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    status: "ok",
    service: "ChatFlow API",
    uptime: process.uptime().toFixed(2) + "s",
    timestamp: new Date().toISOString(),
    online: onlineUsers.size,
  });
});

app.get("/", (req, res) => {
  res.json({
    name: "ChatFlow API",
    version: "1.0.0",
    routes: {
      auth: ["POST /auth/register", "POST /auth/login", "GET /auth/me", "PATCH /auth/me"],
      users: ["GET /users/search?q=", "GET /users/:id"],
      chats: [
        "POST /chats/create",
        "GET /chats",
        "GET /chats/:id",
        "PATCH /chats/:id",
        "POST /chats/:id/members",
        "DELETE /chats/:id/members/:userId",
      ],
      messages: ["POST /messages/send", "GET /messages/:chatId", "PATCH /messages/:id", "DELETE /messages/:id"],
      reactions: ["POST /messages/react"],
      friends: [
        "POST /friends/request",
        "POST /friends/accept",
        "POST /friends/reject",
        "POST /friends/block",
        "POST /friends/unblock",
        "GET /friends",
        "GET /friends/requests",
        "GET /friends/status/:userId",
      ],
    },
  });
});

// 404 fallback
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.method} ${req.path} not found` });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error("[Unhandled Error]", err);
  res.status(500).json({ success: false, message: "Internal server error" });
});

// ===============================================================
//  START SERVER
// ===============================================================

async function start() {
  try {
    await connectDB();
    server.listen(PORT, () => {
      console.log(`
+-----------------------------------------------------+
|           ChatFlow API is Running                   |
+-----------------------------------------------------+
|  HTTP  ->  http://localhost:${PORT}                    |
|  WS    ->  ws://localhost:${PORT}                      |
|  DB    ->  ${DB_NAME.padEnd(39)}|
|  CORS  ->  ${CLIENT_URL.padEnd(39)}|
+-----------------------------------------------------+
      `);
    });
  } catch (err) {
    console.error("[FATAL] Failed to start server:", err);
    process.exit(1);
  }
}

start();