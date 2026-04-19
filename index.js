// ============================================================================
// ChatFlow Backend — Production-Ready Single-File Architecture
// Express + Socket.IO + MongoDB (Native Driver)
// Version: 2.0.1
// ============================================================================

'use strict';

require('dotenv').config();

// ============================================================================
// SECTION 0: ENV GUARD
// ============================================================================

if (!process.env.MONGO_URL) {
  console.error('[FATAL] Missing MONGO_URL in environment. Set it in .env');
  process.exit(1);
}

const express = require('express');
const { createServer } = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const streamifier = require('streamifier');
const webpush = require('web-push');
const axios = require('axios');
const cheerio = require('cheerio');

const SALT_ROUNDS = 10;

// Configure Cloudinary from env
if (process.env.CLOUDINARY_URL) {
  // CLOUDINARY_URL auto-configures cloudinary
} else if (process.env.CLOUDINARY_CLOUD_NAME) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
}

// Multer: store files in memory (we stream to Cloudinary)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB
});

// ============================================================================
// SECTION 1: CONFIGURATION
// ============================================================================

const CONFIG = {
  port: process.env.PORT || 3001,
  mongoUri: process.env.MONGO_URL,
  dbName: process.env.DB_NAME || 'chatflow',
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    credentials: true,
  },
  pagination: {
    defaultLimit: 50,
    maxLimit: 100,
  },
  typing: {
    throttleMs: 2000,
    expireMs: 3000,
  },
  onlineStatus: {
    debounceMs: 5000,
  },
  validation: {
    maxMessageLength: 5000,
    maxUsernameLength: 50,
    maxAttachmentSize: 50 * 1024 * 1024, // 50 MB
    maxAttachments: 10,
    allowedAttachmentTypes: ['image', 'video', 'file', 'voice'],
    maxReactionLength: 8,
    maxPayloadSize: '5mb',
  },
  cache: {
    userTtlMs: 5 * 60 * 1000,
  },
  vapid: {
    publicKey: process.env.VAPID_PUBLIC_KEY,
    privateKey: process.env.VAPID_PRIVATE_KEY,
    email: process.env.VAPID_EMAIL || 'mailto:support@chatflow.com',
  },
};

webpush.setVapidDetails(
  CONFIG.vapid.email,
  CONFIG.vapid.publicKey,
  CONFIG.vapid.privateKey
);

// ============================================================================
// SECTION 2: HELPERS — Validation & Sanitization
// ============================================================================

function isValidObjectId(str) {
  if (!str || typeof str !== 'string') return false;
  return /^[a-fA-F0-9]{24}$/.test(str);
}

function toObjectId(str) {
  if (!isValidObjectId(str)) return null;
  try {
    return new ObjectId(str);
  } catch {
    return null;
  }
}

function sanitizeText(text, maxLength = CONFIG.validation.maxMessageLength) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
    .trim()
    .slice(0, maxLength);
}

function isNonEmptyString(val) {
  return typeof val === 'string' && val.trim().length > 0;
}

function isValidReaction(reaction) {
  if (typeof reaction !== 'string') return false;
  const trimmed = reaction.trim();
  return trimmed.length > 0 && Buffer.byteLength(trimmed, 'utf8') <= CONFIG.validation.maxReactionLength;
}

function validateAttachment(att) {
  if (!att || typeof att !== 'object') return null;
  const { url, type, size, name } = att;
  if (!isNonEmptyString(url)) return null;
  if (!CONFIG.validation.allowedAttachmentTypes.includes(type)) return null;
  if (typeof size !== 'number' || size <= 0 || size > CONFIG.validation.maxAttachmentSize) return null;
  if (!isNonEmptyString(name)) return null;
  return {
    url: sanitizeText(url, 2048),
    type,
    size,
    name: sanitizeText(name, 255),
  };
}

function validateAttachments(attachments) {
  if (!Array.isArray(attachments)) return [];
  return attachments
    .slice(0, CONFIG.validation.maxAttachments)
    .map(validateAttachment)
    .filter(Boolean);
}

async function getOrCreateDirectChat(db, userAId, userBId) {
  const participants = [String(userAId), String(userBId)].sort();
  const existing = await db.collection('chats').findOne({
    type: 'direct',
    participants: { $all: participants, $size: 2 }
  });
  if (existing) return existing;

  const newChat = {
    type: 'direct',
    participants,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastMessage: null,
    metadata: {}
  };
  const result = await db.collection('chats').insertOne(newChat);
  return { _id: result.insertedId, ...newChat };
}

async function resolveChat(db, currentUserId, idOrUserId) {
  if (!idOrUserId) return null;
  const idStr = String(idOrUserId);
  const objId = toObjectId(idStr);
  if (!objId) return null;

  // 1. Check if it's an existing Chat
  const chat = await db.collection('chats').findOne({
    _id: objId,
    participants: String(currentUserId)
  });
  if (chat) return chat;

  // 2. Check if it's a User ID for a direct chat
  const otherUser = await db.collection('users').findOne({ _id: objId }, { projection: { _id: 1 } });
  if (otherUser) {
    return await getOrCreateDirectChat(db, currentUserId, idStr);
  }

  return null;
}

function ensureChatIdString(chatId) {
  if (!chatId) return null;
  if (isValidObjectId(String(chatId))) return String(chatId);
  if (chatId instanceof ObjectId) return String(chatId);
  return null;
}

async function sendPushNotification(db, userId, payload) {
  try {
    const subscriptions = await db.collection('pushSubscriptions').find({ userId: String(userId) }).toArray();
    if (subscriptions.length === 0) return;

    const pushPayload = JSON.stringify(payload);
    const results = await Promise.allSettled(
      subscriptions.map((sub) => {
        const { subscription } = sub;
        return webpush.sendNotification(subscription, pushPayload);
      })
    );

    // Cleanup expired subscriptions
    for (let i = 0; i < results.length; i++) {
      if (results[i].status === 'rejected') {
        const err = results[i].reason;
        if (err.statusCode === 404 || err.statusCode === 410) {
          await db.collection('pushSubscriptions').deleteOne({ _id: subscriptions[i]._id });
        }
      }
    }
  } catch (err) {
    console.error('[Push] Error sending notification:', err.message);
  }
}

async function getLinkPreview(db, url) {
  try {
    const cached = await db.collection('linkPreviews').findOne({ url });
    if (cached) return cached.preview;

    const { data: html } = await axios.get(url, {
      timeout: 5000,
      headers: { 'User-Agent': 'ChatFlow-Bot/1.0' }
    });
    const $ = cheerio.load(html);

    const preview = {
      url,
      title: $('meta[property="og:title"]').attr('content') || $('title').text() || '',
      description: $('meta[property="og:description"]').attr('content') || $('meta[name="description"]').attr('content') || '',
      image: $('meta[property="og:image"]').attr('content') || '',
      siteName: $('meta[property="og:site_name"]').attr('content') || '',
    };

    // Only cache if we got something meaningful
    if (preview.title) {
      await db.collection('linkPreviews').updateOne(
        { url },
        { $set: { url, preview, createdAt: new Date().toISOString() } },
        { upsert: true }
      );
    }

    return preview.title ? preview : null;
  } catch (err) {
    console.error('[LinkPreview] Error:', err.message);
    return null;
  }
}

function isValidWhatsapp(value) {
  if (typeof value !== 'string') return false;
  const cleaned = value.replace(/[^\d]/g, '');
  return cleaned.length >= 7 && cleaned.length <= 20;
}

function isValidUsername(value) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (trimmed.length < 3 || trimmed.length > CONFIG.validation.maxUsernameLength) return false;
  return /^[a-zA-Z0-9_.\-]+$/.test(trimmed);
}

// ============================================================================
// SECTION 3: NORMALIZATION LAYER
// ============================================================================

function normalizeMessage(msg) {
  if (!msg) return null;
  const normalized = {
    id: String(msg._id || msg.id),
    chatId: ensureChatIdString(msg.chatId) || '',
    senderId: String(msg.senderId || ''),
    content: msg.content || '',
    text: msg.content || '', // Alias for frontend compatibility
    type: msg.type || 'text',
    attachments: Array.isArray(msg.attachments) ? msg.attachments : [],
    reactions: msg.reactions || {},
    mentions: Array.isArray(msg.mentions) ? msg.mentions : [],
    replyTo: msg.replyTo ? String(msg.replyTo) : null,
    status: msg.status || 'sent',
    isEdited: Boolean(msg.isEdited),
    isDeleted: Boolean(msg.isDeleted),
    clientMessageId: msg.clientMessageId || null,
    metadata: msg.metadata || {},
    createdAt: msg.createdAt || new Date().toISOString(),
    updatedAt: msg.updatedAt || msg.createdAt || new Date().toISOString(),
  };
  if (msg.sender) normalized.sender = normalizeUser(msg.sender);
  return normalized;
}

function normalizeUser(user) {
  if (!user) return null;
  return {
    id: String(user._id || user.id),
    username: user.username || '',
    displayName: user.displayName || user.username || '',
    avatar: user.avatar || null,
    isOnline: Boolean(user.isOnline),
    lastSeenAt: user.lastSeenAt || null,
    isAdmin: Boolean(user.isAdmin),
    isGuest: Boolean(user.isGuest),
  };
}

function normalizeChat(chat) {
  if (!chat) return null;
  return {
    id: ensureChatIdString(chat._id || chat.id) || '',
    type: chat.type || 'direct',
    name: chat.name || null,
    participants: Array.isArray(chat.participants)
      ? chat.participants.map((p) => (typeof p === 'object' ? normalizeUser(p) : String(p)))
      : [],
    lastMessage: chat.lastMessage ? normalizeMessage(chat.lastMessage) : null,
    groupRoles: chat.groupRoles || {},
    unreadCount: chat.unreadCount || 0,
    createdAt: chat.createdAt || new Date().toISOString(),
    updatedAt: chat.updatedAt || chat.createdAt || new Date().toISOString(),
  };
}

// ============================================================================
// SECTION 4: SOCKET EVENT BUILDER
// ============================================================================

function buildSocketEvent(type, data, meta = {}) {
  return {
    type,
    data,
    meta: {
      chatId: meta.chatId ? ensureChatIdString(meta.chatId) : null,
      userId: meta.userId ? String(meta.userId) : null,
      timestamp: meta.timestamp || new Date().toISOString(),
    },
  };
}

function safeEmit(io, room, event, payload) {
  try {
    if (room) io.to(room).emit(event, payload);
  } catch (err) {
    console.error(`[SafeEmit] Failed to emit ${event} to ${room}:`, err.message);
  }
}

function safeSocketEmit(socket, event, payload) {
  try {
    if (socket && socket.connected) socket.emit(event, payload);
  } catch (err) {
    console.error(`[SafeSocketEmit] Failed to emit ${event}:`, err.message);
  }
}

// ============================================================================
// SECTION 5: IN-MEMORY CACHES & STATE
// ============================================================================

const onlineUsers = new Map();
const typingState = new Map();
const userCache = new Map();

async function getCachedUser(db, userId) {
  const cached = userCache.get(userId);
  if (cached && Date.now() - cached.fetchedAt < CONFIG.cache.userTtlMs) return cached.data;
  const oid = toObjectId(userId);
  if (!oid) return null;
  const user = await db.collection('users').findOne(
    { _id: oid },
    { projection: { username: 1, displayName: 1, avatar: 1, lastSeenAt: 1, isAdmin: 1, isGuest: 1 } }
  );
  if (user) {
    const normalized = normalizeUser(user);
    userCache.set(userId, { data: normalized, fetchedAt: Date.now() });
    return normalized;
  }
  return null;
}

async function batchGetUsers(db, userIds) {
  const results = new Map();
  const toFetch = [];
  for (const uid of userIds) {
    const cached = userCache.get(uid);
    if (cached && Date.now() - cached.fetchedAt < CONFIG.cache.userTtlMs) {
      results.set(uid, cached.data);
    } else {
      toFetch.push(uid);
    }
  }
  if (toFetch.length > 0) {
    const oids = toFetch.map(toObjectId).filter(Boolean);
    if (oids.length > 0) {
      const users = await db
        .collection('users')
        .find({ _id: { $in: oids } }, { projection: { username: 1, displayName: 1, avatar: 1, lastSeenAt: 1, isAdmin: 1, isGuest: 1 } })
        .toArray();
      for (const user of users) {
        const normalized = normalizeUser(user);
        const uid = String(user._id);
        userCache.set(uid, { data: normalized, fetchedAt: Date.now() });
        results.set(uid, normalized);
      }
    }
  }
  return results;
}

function invalidateUserCache(userId) {
  userCache.delete(userId);
}

// ============================================================================
// SECTION 6: ONLINE STATUS MANAGEMENT
// ============================================================================

function setUserOnline(io, db, userId, socketId) {
  let entry = onlineUsers.get(userId);
  if (!entry) {
    entry = { socketIds: new Set(), isOnline: false, lastSeenAt: new Date(), debounceTimer: null };
    onlineUsers.set(userId, entry);
  }
  entry.socketIds.add(socketId);
  if (entry.debounceTimer) clearTimeout(entry.debounceTimer);
  if (!entry.isOnline) {
    entry.debounceTimer = setTimeout(async () => {
      entry.isOnline = true;
      entry.lastSeenAt = new Date();
      const oid = toObjectId(userId);
      if (oid) {
        await db.collection('users').updateOne({ _id: oid }, { $set: { isOnline: true, lastSeenAt: entry.lastSeenAt } }).catch(() => {});
      }
      invalidateUserCache(userId);
      const event = buildSocketEvent('user:online', { user: { id: userId, isOnline: true, lastSeenAt: entry.lastSeenAt.toISOString() } }, { userId });
      safeEmit(io, `user:${userId}:friends`, 'user:online', event);
    }, CONFIG.onlineStatus.debounceMs);
  }
}

function setUserOffline(io, db, userId, socketId) {
  const entry = onlineUsers.get(userId);
  if (!entry) return;
  entry.socketIds.delete(socketId);
  if (entry.socketIds.size === 0) {
    if (entry.debounceTimer) clearTimeout(entry.debounceTimer);
    entry.debounceTimer = setTimeout(async () => {
      if (entry.socketIds.size > 0) return;
      entry.isOnline = false;
      entry.lastSeenAt = new Date();
      const oid = toObjectId(userId);
      if (oid) {
        await db.collection('users').updateOne({ _id: oid }, { $set: { isOnline: false, lastSeenAt: entry.lastSeenAt } }).catch(() => {});
      }
      invalidateUserCache(userId);
      const event = buildSocketEvent('user:offline', { user: { id: userId, isOnline: false, lastSeenAt: entry.lastSeenAt.toISOString() } }, { userId });
      safeEmit(io, `user:${userId}:friends`, 'user:offline', event);
      onlineUsers.delete(userId);
    }, CONFIG.onlineStatus.debounceMs);
  }
}

// ============================================================================
// SECTION 7: TYPING INDICATOR MANAGEMENT
// ============================================================================

async function handleTypingStart(socket, io, db, chatId, userId, username) {
  const key = `${chatId}:${userId}`;
  const now = Date.now();
  const existing = typingState.get(key);
  if (existing && now - existing.lastEmitAt < CONFIG.typing.throttleMs) {
    clearTimeout(existing.timer);
    existing.timer = setTimeout(() => handleTypingStop(socket, io, db, chatId, userId, username), CONFIG.typing.expireMs);
    return;
  }
  if (existing?.timer) clearTimeout(existing.timer);
  const timer = setTimeout(() => handleTypingStop(socket, io, db, chatId, userId, username), CONFIG.typing.expireMs);
  typingState.set(key, { timer, lastEmitAt: now });
  
  const event = buildSocketEvent('typing:start', { username: username || 'Unknown' }, { chatId, userId });
  // Bug 2 Fix: Use socket.to() to exclude the sender from their own typing event
  if (socket) {
    socket.to(`chat:${chatId}`).emit('typing:start', event);
  } else {
    safeEmit(io, `chat:${chatId}`, 'typing:start', event);
  }
  
  // Also notify individual participants to ensure cross-account delivery
  const chat = await db.collection('chats').findOne({ _id: toObjectId(chatId) }, { projection: { participants: 1 } });
  if (chat) {
    chat.participants.forEach(pid => {
      if (String(pid) !== String(userId)) {
        // Individual rooms usually handle one socket each, io is safest here as we aren't broadcasting to the sender's user room anyway
        safeEmit(io, `user:${pid}`, 'typing:start', event);
      }
    });
  }
}

async function handleTypingStop(socket, io, db, chatId, userId, username) {
  const key = `${chatId}:${userId}`;
  const existing = typingState.get(key);
  if (existing?.timer) clearTimeout(existing.timer);
  typingState.delete(key);
  
  const event = buildSocketEvent('typing:stop', { username: username || 'Unknown' }, { chatId, userId });
  if (socket) {
    socket.to(`chat:${chatId}`).emit('typing:stop', event);
  } else {
    safeEmit(io, `chat:${chatId}`, 'typing:stop', event);
  }

  // Also notify individual participants
  const chat = await db.collection('chats').findOne({ _id: toObjectId(chatId) }, { projection: { participants: 1 } });
  if (chat) {
    chat.participants.forEach(pid => {
      if (String(pid) !== String(userId)) {
        safeEmit(io, `user:${pid}`, 'typing:stop', event);
      }
    });
  }
}

// ============================================================================
// SECTION 8: RESPONSE HELPERS
// ============================================================================

function errorResponse(res, status, message, errorCode = null) {
  const body = { success: false, message };
  if (errorCode) body.errorCode = errorCode;
  return res.status(status).json(body);
}

function successResponse(res, data, status = 200) {
  return res.status(status).json({ success: true, ...data });
}

// ============================================================================
// SECTION 9: AUTH HELPERS
// ============================================================================

function authMiddleware(db) {
  return async (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return errorResponse(res, 401, 'Authentication required', 'AUTH_REQUIRED');
      }
      const token = authHeader.split(' ')[1];
      if (!token) return errorResponse(res, 401, 'Invalid token', 'INVALID_TOKEN');

      const session = await db.collection('sessions').findOne({ token }, { projection: { userId: 1 } });
      if (!session) return errorResponse(res, 401, 'Session expired or invalid', 'SESSION_EXPIRED');

      const user = await getCachedUser(db, String(session.userId));
      if (!user) return errorResponse(res, 401, 'User not found', 'USER_NOT_FOUND');

      req.user = {
        id: user.id,
        username: user.username,
        displayName: user.displayName,
        avatar: user.avatar,
        isAdmin: Boolean(user.isAdmin),
        isGuest: Boolean(user.isGuest),
      };
      req.userId = user.id;
      next();
    } catch (err) {
      console.error('[Auth] Error:', err.message);
      return errorResponse(res, 500, 'Authentication error', 'AUTH_ERROR');
    }
  };
}

function requireAdmin(req, res, next) {
  if (!req.user) return errorResponse(res, 401, 'Authentication required', 'AUTH_REQUIRED');
  if (!req.user.isAdmin) return errorResponse(res, 403, 'Admin access required', 'ADMIN_ONLY');
  next();
}

function blockGuests(req, res, next) {
  if (req.user?.isGuest) return errorResponse(res, 403, 'Guest accounts cannot perform this action', 'GUEST_FORBIDDEN');
  next();
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createSession(db, userId) {
  const token = generateToken();
  await db.collection('sessions').insertOne({ token, userId: String(userId), createdAt: new Date() });
  return token;
}

// ============================================================================
// SECTION 10: SERVER START
// ============================================================================

async function startServer() {
  const mongoClient = new MongoClient(CONFIG.mongoUri);
  await mongoClient.connect();
  const db = mongoClient.db(CONFIG.dbName);
  console.log('[MongoDB] Connected to', CONFIG.dbName);

  const activeCalls = new Map(); // socketId -> { callId, otherId, targetUserId }

  await Promise.all([
    db.collection('messages').createIndex({ chatId: 1, createdAt: -1 }),
    db.collection('messages').createIndex({ senderId: 1, status: 1 }),
    db.collection('messages').createIndex({ clientMessageId: 1 }, { unique: true, sparse: true }),
    db.collection('chats').createIndex({ participants: 1, updatedAt: -1 }),
    db.collection('users').createIndex({ username: 1 }, { unique: true }),
    db.collection('users').createIndex({ usernameLower: 1 }, { unique: true, sparse: true }),
    db.collection('users').createIndex({ displayName: 1 }),
    db.collection('sessions').createIndex({ token: 1 }, { unique: true }),
    db.collection('forgotPasswordRequests').createIndex({ status: 1, createdAt: -1 }),
    db.collection('pushSubscriptions').createIndex({ userId: 1 }),
    db.collection('linkPreviews').createIndex({ url: 1 }, { unique: true }),
    db.collection('forgotPasswordRequests').createIndex(
      { username: 1, whatsapp: 1, status: 1 },
      { partialFilterExpression: { status: 'pending' } }
    ),
  ]).catch((err) => console.warn('[MongoDB] Index warning:', err.message));

  const app = express();
  const httpServer = createServer(app);

  app.use(express.json({ limit: CONFIG.validation.maxPayloadSize }));

  // CORS
  app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', CONFIG.cors.origin);
    res.header('Access-Control-Allow-Methods', CONFIG.cors.methods.join(','));
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
    if (req.method === 'OPTIONS') return res.sendStatus(204);
    next();
  });

  const auth = authMiddleware(db);

  const io = new Server(httpServer, {
    cors: CONFIG.cors,
    pingTimeout: 60000,
    pingInterval: 25000,
    maxHttpBufferSize: 1e6,
  });

  // ==========================================================================
  // SECTION 11a: AUTH ROUTES
  // ==========================================================================

  // POST /api/auth/register
  app.post('/api/auth/register', async (req, res) => {
    try {
      let { username, displayName, password, avatar } = req.body;

      if (!isValidUsername(username)) {
        return errorResponse(res, 400, 'Username must be 3-50 chars (letters, numbers, _ . -)', 'INVALID_USERNAME');
      }
      if (!password || typeof password !== 'string' || password.length < 6) {
        return errorResponse(res, 400, 'Password must be at least 6 characters', 'INVALID_PASSWORD');
      }

      const usernameLower = username.toLowerCase();
      displayName = sanitizeText(displayName || username, CONFIG.validation.maxUsernameLength);
      avatar = avatar || `https://api.dicebear.com/7.x/thumbs/svg?seed=${usernameLower}`;

      const existing = await db.collection('users').findOne({ usernameLower });
      if (existing) return errorResponse(res, 409, 'Username already taken', 'USERNAME_TAKEN');

      const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
      const now = new Date();

      const result = await db.collection('users').insertOne({
        username,
        usernameLower,
        displayName,
        passwordHash,
        avatar,
        isAdmin: false,
        isGuest: false,
        isOnline: false,
        createdAt: now,
        lastSeenAt: now,
      });

      const token = await createSession(db, result.insertedId);

      successResponse(res, {
        token,
        user: {
          id: String(result.insertedId),
          username,
          displayName,
          avatar,
          isAdmin: false,
          isGuest: false,
          createdAt: now.toISOString(),
        },
      }, 201);
    } catch (err) {
      if (err.code === 11000) return errorResponse(res, 409, 'Username already taken', 'USERNAME_TAKEN');
      console.error('[POST /api/auth/register] Error:', err.message);
      errorResponse(res, 500, 'Registration failed', 'REGISTER_ERROR');
    }
  });

  // POST /api/auth/login
  app.post('/api/auth/login', async (req, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return errorResponse(res, 400, 'Username and password required', 'MISSING_CREDENTIALS');
      }

      const user = await db.collection('users').findOne({ usernameLower: username.toLowerCase() });
      if (!user) return errorResponse(res, 401, 'Invalid credentials', 'INVALID_CREDENTIALS');

      const match = await bcrypt.compare(password, user.passwordHash);
      if (!match) return errorResponse(res, 401, 'Invalid credentials', 'INVALID_CREDENTIALS');

      await db.collection('users').updateOne({ _id: user._id }, { $set: { lastSeenAt: new Date() } });
      invalidateUserCache(String(user._id));

      const token = await createSession(db, user._id);

      successResponse(res, { token, user: normalizeUser(user) });
    } catch (err) {
      console.error('[POST /api/auth/login] Error:', err.message);
      errorResponse(res, 500, 'Login failed', 'LOGIN_ERROR');
    }
  });

  // POST /api/auth/logout
  app.post('/api/auth/logout', auth, async (req, res) => {
    try {
      const token = req.headers.authorization.split(' ')[1];
      await db.collection('sessions').deleteOne({ token });
      successResponse(res, { message: 'Logged out' });
    } catch (err) {
      console.error('[POST /api/auth/logout] Error:', err.message);
      errorResponse(res, 500, 'Logout failed', 'LOGOUT_ERROR');
    }
  });

  // GET /api/auth/me
  app.get('/api/auth/me', auth, async (req, res) => {
    successResponse(res, { user: req.user });
  });



  // POST /api/auth/profile
  app.post('/api/auth/profile', auth, async (req, res) => {
    try {
      const { displayName, avatar, about } = req.body;
      const patch = {};
      if (typeof displayName === 'string') patch.displayName = sanitizeText(displayName, 50);
      if (typeof avatar === 'string') patch.avatar = avatar; // Base64 or URL
      if (typeof about === 'string') patch.about = sanitizeText(about, 200);

      if (Object.keys(patch).length === 0) return errorResponse(res, 400, 'Nothing to update', 'EMPTY_PATCH');

      await db.collection('users').updateOne({ _id: toObjectId(req.userId) }, { $set: patch });
      const updated = await getCachedUser(db, req.userId);
      
      // Notify other users about name/avatar change if needed
      // (Simplified: relies on next fetch or presence)

      successResponse(res, { user: updated });
    } catch (err) {
      console.error('[POST /api/auth/profile] Error:', err.message);
      errorResponse(res, 500, 'Failed to update profile', 'PROFILE_UPDATE_ERROR');
    }
  });

  // POST /api/auth/forgot-password
  app.post('/api/auth/forgot-password', async (req, res) => {
    try {
      const username = sanitizeText(req.body?.username || '', CONFIG.validation.maxUsernameLength);
      const whatsapp = sanitizeText(req.body?.whatsapp || '', 32);
      if (!isValidUsername(username)) return errorResponse(res, 400, 'Invalid username', 'INVALID_USERNAME');
      if (!isValidWhatsapp(whatsapp)) return errorResponse(res, 400, 'Invalid WhatsApp number', 'INVALID_WHATSAPP');

      const existing = await db.collection('forgotPasswordRequests').findOne(
        { username, whatsapp, status: 'pending' },
        { projection: { _id: 1 } }
      );
      if (existing) return errorResponse(res, 409, 'A pending request already exists', 'DUPLICATE_REQUEST');

      const doc = { username, whatsapp, status: 'pending', createdAt: new Date() };
      const result = await db.collection('forgotPasswordRequests').insertOne(doc);

      successResponse(res, {
        request: { id: String(result.insertedId), username: doc.username, whatsapp: doc.whatsapp, status: doc.status, createdAt: doc.createdAt.toISOString() },
      }, 201);
    } catch (err) {
      console.error('[POST /api/auth/forgot-password] Error:', err.message);
      errorResponse(res, 500, 'Failed to submit request', 'FORGOT_PASSWORD_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 11b: HEALTH
  // ==========================================================================

  app.get('/api/health', (req, res) => {
    successResponse(res, { status: 'ok', uptime: process.uptime(), online: onlineUsers.size });
  });

  // ==========================================================================
  // SECTION 11c: USER ROUTES
  // ==========================================================================

  app.get('/api/users/search', auth, async (req, res) => {
    try {
      const rawQ = req.query?.q;
      if (typeof rawQ !== 'string' || rawQ.trim().length < 1) {
        return errorResponse(res, 400, 'Search query required', 'EMPTY_QUERY');
      }
      const sanitizedQuery = sanitizeText(rawQ, 100);
      if (!sanitizedQuery) return successResponse(res, { users: [] });

      console.log(`[GET /api/users/search] query="${sanitizedQuery}" user="${req.userId}"`);

      const escaped = sanitizedQuery.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex = new RegExp(escaped, 'i');

      const selfId = req.userId;
      const selfOid = isValidObjectId(selfId) ? toObjectId(selfId) : null;

      const filter = {
        $or: [{ usernameLower: regex }, { username: regex }, { displayName: regex }],
        isGuest: { $ne: true },
      };

      if (selfOid) {
        filter._id = { $ne: selfOid };
      }

      const users = await db
        .collection('users')
        .find(filter, {
          projection: { username: 1, displayName: 1, avatar: 1, lastSeenAt: 1, isAdmin: 1, isGuest: 1 },
        })
        .limit(20)
        .toArray();

      const normalized = users.map((u) => {
        const n = normalizeUser(u);
        const onlineEntry = onlineUsers.get(n.id);
        if (onlineEntry) {
          n.isOnline = onlineEntry.isOnline;
          n.lastSeenAt = onlineEntry.lastSeenAt?.toISOString?.() || n.lastSeenAt;
        }
        return n;
      });

      successResponse(res, { users: normalized });
    } catch (err) {
      console.error('[GET /api/users/search] Error:', err.message);
      errorResponse(res, 500, 'Search failed', 'SEARCH_ERROR');
    }
  });

  app.get('/api/users/:userId', auth, async (req, res) => {
    try {
      const userId = req.params.userId;
      if (!isValidObjectId(userId)) return errorResponse(res, 400, 'Invalid userId', 'INVALID_USER_ID');
      const user = await getCachedUser(db, userId);
      if (!user) return errorResponse(res, 404, 'User not found', 'USER_NOT_FOUND');
      const onlineEntry = onlineUsers.get(userId);
      if (onlineEntry) {
        user.isOnline = onlineEntry.isOnline;
        user.lastSeenAt = onlineEntry.lastSeenAt?.toISOString() || user.lastSeenAt;
      }
      successResponse(res, { user });
    } catch (err) {
      console.error('[GET /api/users] Error:', err.message);
      errorResponse(res, 500, 'Failed to fetch user', 'FETCH_USER_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 11d: CHAT ROUTES
  // ==========================================================================

  app.get('/api/chats', auth, async (req, res) => {
    try {
      const chats = await db
        .collection('chats')
        .find({ participants: req.userId }, { projection: { type: 1, name: 1, participants: 1, lastMessage: 1, updatedAt: 1 } })
        .sort({ updatedAt: -1 })
        .limit(100)
        .toArray();

      const allParticipantIds = [...new Set(chats.flatMap((c) => c.participants || []))];
      const usersMap = await batchGetUsers(db, allParticipantIds);

      const normalized = chats.map((chat) => {
        const c = normalizeChat(chat);
        c.unreadCount = chat.unreadCounts?.[req.userId] || 0;
        // Only keep summary info for sidebar
        c.participants = (chat.participants || []).map((pid) => {
            const u = usersMap.get(String(pid));
            return u ? { id: u.id, username: u.username, displayName: u.displayName, avatar: u.avatar } : { id: String(pid) };
        });
        return c;
      });

      successResponse(res, { chats: normalized });
    } catch (err) {
      console.error('[GET /api/chats] Error:', err.message);
      errorResponse(res, 500, 'Failed to fetch chats', 'FETCH_CHATS_ERROR');
    }
  });

  app.post('/api/chats', auth, async (req, res) => {
    try {
      const { type, participantIds, name } = req.body;
      if (!Array.isArray(participantIds) || participantIds.length === 0) {
        return errorResponse(res, 400, 'participantIds required', 'INVALID_PARTICIPANTS');
      }
      const validIds = participantIds.filter(isValidObjectId);
      if (validIds.length !== participantIds.length) {
        return errorResponse(res, 400, 'Invalid participant ID(s)', 'INVALID_PARTICIPANT_ID');
      }
      const allParticipants = [...new Set([req.userId, ...validIds])];

      if (type === 'direct' && allParticipants.length === 2) {
        const existing = await db.collection('chats').findOne({ type: 'direct', participants: { $all: allParticipants, $size: 2 } });
        if (existing) return successResponse(res, { chat: normalizeChat(existing) });
      }

      const unreadCounts = {};
      allParticipants.forEach(p => { unreadCounts[p] = 0; });

      const now = new Date().toISOString();
      const chatDoc = {
        type: type || 'direct',
        name: name ? sanitizeText(name, CONFIG.validation.maxUsernameLength) : null,
        participants: allParticipants,
        ...(type === 'group' ? { groupRoles: { [req.userId]: 'owner' } } : {}),
        lastMessage: null,
        unreadCounts,
        createdAt: now,
        updatedAt: now,
      };
      const result = await db.collection('chats').insertOne(chatDoc);
      chatDoc._id = result.insertedId;

      const normalized = normalizeChat(chatDoc);
      // Notify all participants about the new chat so they can join the room
      allParticipants.forEach((pid) => {
        safeEmit(io, `user:${pid}`, 'chat:created', buildSocketEvent('chat:created', { chat: normalized }, { chatId: String(result.insertedId) }));
      });

      successResponse(res, { chat: normalized }, 201);
    } catch (err) {
      console.error('[POST /api/chats] Error:', err.message);
      errorResponse(res, 500, 'Failed to create chat', 'CREATE_CHAT_ERROR');
    }
  });

  // ADD MEMBER TO GROUP
  app.post('/api/chats/:chatId/members', auth, async (req, res) => {
    try {
      let chatIdStr = req.params.chatId;
      if (!isValidObjectId(chatIdStr)) return errorResponse(res, 400, 'Invalid chatId', 'INVALID_CHAT_ID');
      const { memberId } = req.body;
      if (!isValidObjectId(memberId)) return errorResponse(res, 400, 'Invalid memberId', 'INVALID_USER_ID');

      const chatObjId = toObjectId(chatIdStr);
      const chat = await db.collection('chats').findOne({ _id: chatObjId, type: 'group' });
      if (!chat) return errorResponse(res, 404, 'Group not found', 'CHAT_NOT_FOUND');

      const isParticipant = chat.participants.includes(req.userId);
      const isMemberIdParticipant = chat.participants.includes(memberId);

      if (!isParticipant) return errorResponse(res, 403, 'Not a participant', 'NOT_PARTICIPANT');
      if (isMemberIdParticipant) return errorResponse(res, 400, 'User is already a member', 'ALREADY_MEMBER');

      // Check admin permissions
      const role = chat.groupRoles?.[req.userId] || 'member';
      if (role !== 'admin' && role !== 'owner') {
        return errorResponse(res, 403, 'Requires admin privileges', 'INSUFFICIENT_PERMISSIONS');
      }

      await db.collection('chats').updateOne(
        { _id: toObjectId(chatId) },
        { 
          $push: { participants: memberId },
          $set: { [`unreadCounts.${memberId}`]: 0, updatedAt: new Date().toISOString() } 
        }
      );

      const updatedChat = await db.collection('chats').findOne({ _id: chatObjId });
      const normalized = normalizeChat(updatedChat);
      
      updatedChat.participants.forEach((pid) => {
        safeEmit(io, `user:${pid}`, 'chat:updated', buildSocketEvent('chat:updated', { chat: normalized }, { chatId: chatIdStr }));
      });

      successResponse(res, { chat: normalized });
    } catch (err) {
      console.error('[POST /api/chats/:chatId/members] Error:', err.message);
      errorResponse(res, 500, 'Failed to add member', 'ADD_MEMBER_ERROR');
    }
  });

  // KICK MEMBER OR LEAVE GROUP
  app.delete('/api/chats/:chatId/members/:memberId', auth, async (req, res) => {
    try {
      const { chatId, memberId } = req.params;
      if (!isValidObjectId(chatId) || !isValidObjectId(memberId)) return errorResponse(res, 400, 'Invalid ID', 'INVALID_ID');

      const chatObjId = toObjectId(chatId);
      const chat = await db.collection('chats').findOne({ _id: chatObjId, type: 'group' });
      if (!chat) return errorResponse(res, 404, 'Group not found', 'CHAT_NOT_FOUND');

      const isSelf = req.userId === memberId;
      const isParticipant = chat.participants.includes(req.userId);
      
      if (!isParticipant && !isSelf) return errorResponse(res, 403, 'Not a participant', 'NOT_PARTICIPANT');

      if (!isSelf) {
        // Check admin permissions if kicking someone else
        const myRole = chat.groupRoles?.[req.userId] || 'member';
        const targetRole = chat.groupRoles?.[memberId] || 'member';

        if (myRole !== 'admin' && myRole !== 'owner') {
          return errorResponse(res, 403, 'Requires admin privileges', 'INSUFFICIENT_PERMISSIONS');
        }
        if (myRole === 'admin' && (targetRole === 'admin' || targetRole === 'owner')) {
          return errorResponse(res, 403, 'Admin cannot kick another Admin/Owner', 'INSUFFICIENT_PERMISSIONS');
        }
      }

      const updateQuery = {
        $pull: { participants: memberId },
        $unset: { [`groupRoles.${memberId}`]: "" },
        $set: { updatedAt: new Date().toISOString() }
      };

      await db.collection('chats').updateOne({ _id: chatObjId }, updateQuery);
      
      const updatedChat = await db.collection('chats').findOne({ _id: chatObjId });
      
      // If no members left, delete the group
      if (updatedChat.participants.length === 0) {
        await db.collection('chats').deleteOne({ _id: chatObjId });
        await db.collection('messages').deleteMany({ chatId });
        successResponse(res, { deleted: true });
        return;
      }
      
      // Assign new owner if owner leaves
      if (isSelf && chat.groupRoles?.[req.userId] === 'owner') {
        const remainingAdmin = updatedChat.participants.find(p => updatedChat.groupRoles?.[p] === 'admin');
        const newOwner = remainingAdmin || updatedChat.participants[0];
        await db.collection('chats').updateOne({ _id: chatObjId }, { $set: { [`groupRoles.${newOwner}`]: 'owner' } });
      }

      const freshChat = await db.collection('chats').findOne({ _id: chatObjId });
      const normalized = normalizeChat(freshChat);
      
      // Notify kicked member they were removed
      if (!isSelf) {
        safeEmit(io, `user:${memberId}`, 'group:kicked', buildSocketEvent('group:kicked', { chatId }));
      }
      
      // Notify remaining members
      freshChat.participants.forEach((pid) => {
        safeEmit(io, `user:${pid}`, 'chat:updated', buildSocketEvent('chat:updated', { chat: normalized }, { chatId }));
      });
      
      successResponse(res, { chat: normalized });
    } catch (err) {
      console.error('[DELETE /api/chats/:chatId/members/:memberId] Error:', err.message);
      errorResponse(res, 500, 'Failed to remove member', 'REMOVE_MEMBER_ERROR');
    }
  });

  // CHANGE MEMBER ROLE
  app.put('/api/chats/:chatId/members/:memberId/role', auth, async (req, res) => {
    try {
        const { chatId, memberId } = req.params;
        const { role } = req.body; // 'admin' or 'member'
        
        if (!isValidObjectId(chatId) || !isValidObjectId(memberId)) return errorResponse(res, 400, 'Invalid ID', 'INVALID_ID');
        if (role !== 'admin' && role !== 'member') return errorResponse(res, 400, 'Invalid role', 'INVALID_ROLE');
  
        const chatObjId = toObjectId(chatId);
        const chat = await db.collection('chats').findOne({ _id: chatObjId, type: 'group' });
        if (!chat) return errorResponse(res, 404, 'Group not found', 'CHAT_NOT_FOUND');
  
        const myRole = chat.groupRoles?.[req.userId] || 'member';
        const targetRole = chat.groupRoles?.[memberId] || 'member';

        // Only Owner can promote/demote admins
        if (myRole !== 'owner') {
          return errorResponse(res, 403, 'Only the group owner can change admin roles', 'INSUFFICIENT_PERMISSIONS');
        }
        if (targetRole === 'owner') {
          return errorResponse(res, 400, 'Cannot change owner role', 'INVALID_OPERATION');
        }

        const updateKey = `groupRoles.${memberId}`;
        const updateDoc = role === 'member'
          ? { $unset: { [updateKey]: "" }, $set: { updatedAt: new Date().toISOString() } }
          : { $set: { [updateKey]: role, updatedAt: new Date().toISOString() } };

        await db.collection('chats').updateOne({ _id: chatObjId }, updateDoc);
  
        const updatedChat = await db.collection('chats').findOne({ _id: chatObjId });
        const normalized = normalizeChat(updatedChat);
        
        updatedChat.participants.forEach((pid) => {
          safeEmit(io, `user:${pid}`, 'chat:updated', buildSocketEvent('chat:updated', { chat: normalized }, { chatId }));
        });
  
        successResponse(res, { chat: normalized });
    } catch (err) {
      console.error('[PUT role] Error:', err.message);
      errorResponse(res, 500, 'Failed to update user role', 'ROLE_UPDATE_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 11e: MESSAGE ROUTES
  // ==========================================================================

  app.get('/api/messages/:chatId', auth, async (req, res) => {
    try {
      const chatId = ensureChatIdString(req.params.chatId);
      if (!chatId) return errorResponse(res, 400, 'Invalid chatId', 'INVALID_CHAT_ID');

      const chat = await db.collection('chats').findOne({ _id: toObjectId(chatId), participants: req.userId }, { projection: { _id: 1 } });
      if (!chat) return errorResponse(res, 403, 'Not a participant of this chat', 'NOT_PARTICIPANT');

      const { cursor, direction = 'before', limit: rawLimit } = req.query;
      const limit = Math.min(Math.max(parseInt(rawLimit, 10) || CONFIG.pagination.defaultLimit, 1), CONFIG.pagination.maxLimit);
      const query = { chatId };

      if (cursor) {
        let cursorDate;
        if (isValidObjectId(cursor)) {
          const cursorMsg = await db.collection('messages').findOne({ _id: toObjectId(cursor) }, { projection: { createdAt: 1 } });
          cursorDate = cursorMsg?.createdAt;
        } else {
          const parsed = new Date(cursor);
          if (!isNaN(parsed.getTime())) cursorDate = parsed.toISOString();
        }
        if (cursorDate) query.createdAt = direction === 'after' ? { $gt: cursorDate } : { $lt: cursorDate };
      }

      const sortDir = direction === 'after' ? 1 : -1;
      const messages = await db.collection('messages').find(query).sort({ createdAt: sortDir }).limit(limit + 1).toArray();
      const hasMore = messages.length > limit;
      if (hasMore) messages.pop();
      if (direction !== 'after') messages.reverse();

      // Mark fetched messages as DELIVERED if recipient is current user
      const unDelivered = messages.filter(m => m.senderId !== req.userId && m.status === 'sent');
      if (unDelivered.length > 0) {
        const uids = unDelivered.map(m => m._id);
        await db.collection('messages').updateMany({ _id: { $in: uids } }, { $set: { status: 'delivered', updatedAt: new Date().toISOString() } });
        messages.forEach(m => { if (uids.some(uid => String(uid) === String(m._id))) m.status = 'delivered'; });
        
        // Notify senders
        unDelivered.forEach(m => {
          safeEmit(io, `user:${m.senderId}`, 'message:status', buildSocketEvent('message:status', { messageId: String(m._id), status: 'delivered', chatId }, { chatId }));
        });
      }

      const senderIds = [...new Set(messages.map((m) => m.senderId).filter(Boolean))];
      const sendersMap = await batchGetUsers(db, senderIds);
      const normalized = messages.map((msg) => {
        const n = normalizeMessage(msg);
        n.sender = sendersMap.get(msg.senderId) || null;
        return n;
      });

      const nextCursor = hasMore && normalized.length > 0
        ? (direction === 'after' ? normalized[normalized.length - 1].id : normalized[0].id)
        : null;

      successResponse(res, { messages: normalized, nextCursor, hasMore });
    } catch (err) {
      console.error('[GET /api/messages] Error:', err.message);
      errorResponse(res, 500, 'Failed to fetch messages', 'FETCH_MESSAGES_ERROR');
    }
  });

  app.post('/api/messages/:chatId', auth, async (req, res) => {
    try {
      const chat = await resolveChat(db, req.userId, req.params.chatId);
      if (!chat) return errorResponse(res, 400, 'Invalid chat or user ID', 'INVALID_CHAT_ID');
      const chatId = String(chat._id);

      const { content, type, attachments, replyTo, mentions, clientMessageId } = req.body;
      const sanitizedContent = sanitizeText(content || '');
      const validAttachments = validateAttachments(attachments);
      if (!sanitizedContent && validAttachments.length === 0) return errorResponse(res, 400, 'Message must have content or attachments', 'EMPTY_MESSAGE');

      if (clientMessageId && typeof clientMessageId === 'string') {
        const existing = await db.collection('messages').findOne({ clientMessageId }, { projection: { _id: 1, chatId: 1, senderId: 1, content: 1, createdAt: 1 } });
        if (existing) {
          const sender = await getCachedUser(db, req.userId);
          const n = normalizeMessage(existing);
          n.sender = sender;
          return successResponse(res, { message: n, deduplicated: true });
        }
      }

      if (replyTo) {
        if (!isValidObjectId(replyTo)) return errorResponse(res, 400, 'Invalid replyTo ID', 'INVALID_REPLY_TO');
        const replyMsg = await db.collection('messages').findOne({ _id: toObjectId(replyTo), chatId, isDeleted: { $ne: true } }, { projection: { _id: 1 } });
        if (!replyMsg) return errorResponse(res, 400, 'Reply target not found or deleted', 'REPLY_NOT_FOUND');
      }

      let resolvedMentions = [];
      if (Array.isArray(mentions) && mentions.length > 0) {
        const mentionIds = mentions.filter(isValidObjectId);
        const mentionUsers = await batchGetUsers(db, mentionIds);
        resolvedMentions = mentionIds.filter((id) => mentionUsers.has(id));
      }

      const now = new Date().toISOString();
      let linkPreview = null;
      if (sanitizedContent && sanitizedContent.includes('http')) {
        const urlMatch = sanitizedContent.match(/https?:\/\/[^\s]+/);
        if (urlMatch) {
          linkPreview = await getLinkPreview(db, urlMatch[0]);
        }
      }

      const recipients = (chat.participants || []).filter(p => String(p) !== req.userId);
      const isAnyRecipientOnline = recipients.some(pid => {
        const entry = onlineUsers.get(String(pid));
        return entry && entry.isOnline;
      });

      const messageDoc = {
        chatId, senderId: req.userId, content: sanitizedContent, type: type || 'text',
        attachments: validAttachments, reactions: {}, mentions: resolvedMentions,
        replyTo: replyTo || null, isEdited: false, isDeleted: false,
        clientMessageId: clientMessageId || null, status: isAnyRecipientOnline ? 'delivered' : 'sent',
        linkPreview,
        createdAt: now, updatedAt: now,
      };

      const result = await db.collection('messages').insertOne(messageDoc);
      messageDoc._id = result.insertedId;

      const incObj = {};
      (chat.participants || []).forEach(p => { 
        if (String(p) !== req.userId) incObj[`unreadCounts.${p}`] = 1; 
      });

      await db.collection('chats').updateOne(
        { _id: toObjectId(chatId) },
        { 
          $set: { lastMessage: { _id: result.insertedId, content: sanitizedContent, senderId: req.userId, createdAt: now }, updatedAt: now },
          ...(Object.keys(incObj).length > 0 ? { $inc: incObj } : {})
        }
      );

      const sender = await getCachedUser(db, req.userId);
      const normalized = normalizeMessage(messageDoc);
      normalized.sender = sender;

      safeEmit(io, `chat:${chatId}`, 'message:new', buildSocketEvent('message:new', { message: normalized }, { chatId, userId: req.userId }));

      // Bug 3: If marked as delivered, notify the sender immediately so they see the double grey ticks
      if (messageDoc.status === 'delivered') {
        safeEmit(io, `user:${req.userId}`, 'message:status', buildSocketEvent('message:status', { messageId: String(messageDoc._id), status: 'delivered', chatId }, { chatId }));
      }

      // Also notify individual participants (ensures they see it even if they haven't joined the chat room yet)
      const participants = chat.participants || [];
      participants.forEach(async (pid) => {
        if (String(pid) !== req.userId) {
          safeEmit(io, `user:${pid}`, 'message:new', buildSocketEvent('message:new', { message: normalized }, { chatId }));
          if (resolvedMentions.includes(String(pid))) {
            safeEmit(io, `user:${pid}`, 'message:mention', buildSocketEvent('message:mention', { message: normalized }, { chatId }));
          }

          // Trigger Push Notification
          const isMentioned = resolvedMentions.includes(String(pid));
          await sendPushNotification(db, pid, {
            title: isMentioned ? `@${sender.username} mentioned you` : sender.displayName || sender.username,
            body: normalized.text || 'Shared a media',
            tag: chatId,
            data: { chatId, messageId: String(result.insertedId) }
          });
        }
      });

      successResponse(res, { message: normalized }, 201);
    } catch (err) {
      if (err.code === 11000 && err.keyPattern?.clientMessageId) {
        const existing = await db.collection('messages').findOne({ clientMessageId: req.body.clientMessageId });
        if (existing) {
          const sender = await getCachedUser(db, req.userId);
          const n = normalizeMessage(existing);
          n.sender = sender;
          return successResponse(res, { message: n, deduplicated: true });
        }
      }
      console.error('[POST /api/messages] Error:', err.message);
      errorResponse(res, 500, 'Failed to send message', 'SEND_MESSAGE_ERROR');
    }
  });

  // ==========================================================================
  // FILE UPLOAD ROUTE (Voice, Image, Video via Multer → Cloudinary)
  // ==========================================================================

  app.post('/api/messages/upload', auth, upload.single('file'), async (req, res) => {
    try {
      if (!req.file) return errorResponse(res, 400, 'No file uploaded', 'NO_FILE');

      const { chatId, chat_id, type, duration, clientMessageId } = req.body;
      const rawChatId = chatId || chat_id;

      const chat = await resolveChat(db, req.userId, rawChatId);
      if (!chat) return errorResponse(res, 400, 'Invalid chatId or recipient', 'INVALID_CHAT_ID');
      const resolvedChatId = String(chat._id);

      // Deduplicate
      if (clientMessageId && typeof clientMessageId === 'string') {
        const existing = await db.collection('messages').findOne({ clientMessageId }, { projection: { _id: 1 } });
        if (existing) {
          const sender = await getCachedUser(db, req.userId);
          const n = normalizeMessage(existing);
          n.sender = sender;
          return successResponse(res, { message: n, deduplicated: true });
        }
      }

      // Stream upload to Cloudinary
      const fileType = type || (req.file.mimetype.startsWith('image/') ? 'image' : req.file.mimetype.startsWith('audio/') ? 'voice' : 'video');
      const resourceType = (fileType === 'voice' || fileType === 'video') ? 'video' : 'image';
      const folder = `chatflow/${resolvedChatId}`;

      const uploadResult = await new Promise((resolve, reject) => {
        const uploadStream = cloudinary.uploader.upload_stream(
          { resource_type: resourceType, folder, format: type === 'voice' ? 'mp3' : undefined },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        streamifier.createReadStream(req.file.buffer).pipe(uploadStream);
      });

      const fileUrl = uploadResult.secure_url;
      const parsedDuration = parseInt(duration, 10) || Math.round(uploadResult.duration || 0);

      const now = new Date().toISOString();
      const messageDoc = {
        chatId: resolvedChatId,
        senderId: req.userId,
        content: '',
        type: type || 'voice',
        attachments: [{
          type: type || 'voice',
          url: fileUrl,
          size: req.file.size,
          name: req.file.originalname || 'upload',
        }],
        reactions: {},
        mentions: [],
        replyTo: null,
        isEdited: false,
        isDeleted: false,
        clientMessageId: clientMessageId || null,
        status: 'sent',
        metadata: { duration: parsedDuration, cloudinaryId: uploadResult.public_id },
        createdAt: now,
        updatedAt: now,
      };

      const result = await db.collection('messages').insertOne(messageDoc);
      messageDoc._id = result.insertedId;

      // Increment unread counts for other participants
      const incObj = {};
      (chat.participants || []).forEach(p => {
        if (String(p) !== req.userId) incObj[`unreadCounts.${p}`] = 1;
      });

      await db.collection('chats').updateOne(
        { _id: toObjectId(resolvedChatId) },
        {
          $set: {
            lastMessage: { _id: result.insertedId, content: type === 'voice' ? '🎤 Voice message' : '📎 Attachment', senderId: req.userId, createdAt: now },
            updatedAt: now,
          },
          ...(Object.keys(incObj).length > 0 ? { $inc: incObj } : {}),
        }
      );

      const sender = await getCachedUser(db, req.userId);
      const normalized = normalizeMessage(messageDoc);
      normalized.sender = sender;

      // Broadcast to chat room and individual users
      safeEmit(io, `chat:${resolvedChatId}`, 'message:new', buildSocketEvent('message:new', { message: normalized }, { chatId: resolvedChatId, userId: req.userId }));
      (chat.participants || []).forEach(pid => {
        if (String(pid) !== req.userId) {
          safeEmit(io, `user:${pid}`, 'message:new', buildSocketEvent('message:new', { message: normalized }, { chatId: resolvedChatId }));
        }
      });

      successResponse(res, { message: normalized }, 201);
    } catch (err) {
      console.error('[POST /api/messages/upload] Error:', err.message, err.stack);
      errorResponse(res, 500, 'Failed to upload and send message', 'UPLOAD_ERROR');
    }
  });

  app.post('/api/messages/:chatId/read', auth, async (req, res) => {
    try {
      const chatId = ensureChatIdString(req.params.chatId);
      if (!chatId) return errorResponse(res, 400, 'Invalid chatId', 'INVALID_CHAT_ID');

      const chat = await db.collection('chats').findOne({ _id: toObjectId(chatId), participants: req.userId }, { projection: { _id: 1, participants: 1 } });
      if (!chat) return errorResponse(res, 403, 'Not a participant of this chat', 'NOT_PARTICIPANT');

      await db.collection('chats').updateOne(
        { _id: toObjectId(chatId) },
        { $set: { [`unreadCounts.${req.userId}`]: 0 } }
      );

      const now = new Date().toISOString();
      const result = await db.collection('messages').updateMany(
        { chatId, senderId: { $ne: req.userId }, status: { $ne: 'seen' } },
        { $set: { status: 'seen', updatedAt: now } }
      );

      if (result.modifiedCount > 0) {
        const otherParticipant = chat.participants.find(p => String(p) !== req.userId);
        if (otherParticipant) {
          // Bug 3: Notify the sender that their messages were seen
          safeEmit(io, `user:${otherParticipant}`, 'message:status', buildSocketEvent('message:status', { status: 'seen', chatId }, { chatId }));
        }
      }

      successResponse(res, { modifiedCount: result.modifiedCount });
    } catch (err) {
      console.error('[POST /api/messages/read] Error:', err.message);
      errorResponse(res, 500, 'Failed to mark messages as read', 'MARK_READ_ERROR');
    }
  });

  app.put('/api/messages/:messageId', auth, async (req, res) => {
    try {
      const messageId = req.params.messageId;
      if (!isValidObjectId(messageId)) return errorResponse(res, 400, 'Invalid messageId', 'INVALID_MESSAGE_ID');

      const message = await db.collection('messages').findOne({ _id: toObjectId(messageId) }, { projection: { senderId: 1, chatId: 1, isDeleted: 1 } });
      if (!message) return errorResponse(res, 404, 'Message not found', 'MESSAGE_NOT_FOUND');
      if (message.isDeleted) return errorResponse(res, 400, 'Cannot edit a deleted message', 'MESSAGE_DELETED');
      if (message.senderId !== req.userId) return errorResponse(res, 403, "Cannot edit another user's message", 'NOT_MESSAGE_OWNER');

      const sanitizedContent = sanitizeText(req.body?.content || '');
      if (!sanitizedContent) return errorResponse(res, 400, 'Content cannot be empty', 'EMPTY_CONTENT');

      const now = new Date().toISOString();
      await db.collection('messages').updateOne({ _id: toObjectId(messageId) }, { $set: { content: sanitizedContent, isEdited: true, updatedAt: now } });

      const updated = await db.collection('messages').findOne({ _id: toObjectId(messageId) });
      const normalized = normalizeMessage(updated);
      normalized.sender = await getCachedUser(db, req.userId);

      const chatId = ensureChatIdString(message.chatId);
      safeEmit(io, `chat:${chatId}`, 'message:update', buildSocketEvent('message:update', { message: normalized }, { chatId, userId: req.userId }));
      successResponse(res, { message: normalized });
    } catch (err) {
      console.error('[PUT /api/messages] Error:', err.message);
      errorResponse(res, 500, 'Failed to edit message', 'EDIT_MESSAGE_ERROR');
    }
  });

  app.delete('/api/messages/:messageId', auth, async (req, res) => {
    try {
      const messageId = req.params.messageId;
      if (!isValidObjectId(messageId)) return errorResponse(res, 400, 'Invalid messageId', 'INVALID_MESSAGE_ID');

      const message = await db.collection('messages').findOne({ _id: toObjectId(messageId) }, { projection: { senderId: 1, chatId: 1, isDeleted: 1 } });
      if (!message) return errorResponse(res, 404, 'Message not found', 'MESSAGE_NOT_FOUND');
      if (message.isDeleted) return errorResponse(res, 400, 'Message already deleted', 'ALREADY_DELETED');
      if (message.senderId !== req.userId) return errorResponse(res, 403, "Cannot delete another user's message", 'NOT_MESSAGE_OWNER');

      const now = new Date().toISOString();
      await db.collection('messages').updateOne({ _id: toObjectId(messageId) }, { $set: { isDeleted: true, content: '', attachments: [], updatedAt: now } });

      const chatId = ensureChatIdString(message.chatId);
      safeEmit(io, `chat:${chatId}`, 'message:delete', buildSocketEvent('message:delete', { messageId }, { chatId, userId: req.userId }));
      successResponse(res, { messageId });
    } catch (err) {
      console.error('[DELETE /api/messages] Error:', err.message);
      errorResponse(res, 500, 'Failed to delete message', 'DELETE_MESSAGE_ERROR');
    }
  });

  app.post('/api/messages/:messageId/reactions', auth, async (req, res) => {
    try {
      const messageId = req.params.messageId;
      if (!isValidObjectId(messageId)) return errorResponse(res, 400, 'Invalid messageId', 'INVALID_MESSAGE_ID');

      const { reaction } = req.body;
      if (!isValidReaction(reaction)) return errorResponse(res, 400, 'Invalid reaction', 'INVALID_REACTION');

      const message = await db.collection('messages').findOne({ _id: toObjectId(messageId) }, { projection: { chatId: 1, reactions: 1, isDeleted: 1 } });
      if (!message) return errorResponse(res, 404, 'Message not found', 'MESSAGE_NOT_FOUND');
      if (message.isDeleted) return errorResponse(res, 400, 'Cannot react to a deleted message', 'MESSAGE_DELETED');

      const trimmedReaction = reaction.trim();
      const reactions = message.reactions || {};
      const usersForReaction = reactions[trimmedReaction] || [];

      let updatedUsers;
      if (usersForReaction.includes(req.userId)) {
        updatedUsers = usersForReaction.filter((id) => id !== req.userId);
      } else {
        updatedUsers = [...usersForReaction, req.userId];
      }

      if (updatedUsers.length === 0) {
        delete reactions[trimmedReaction];
        await db.collection('messages').updateOne({ _id: toObjectId(messageId) }, { $unset: { [`reactions.${trimmedReaction}`]: '' } });
      } else {
        reactions[trimmedReaction] = updatedUsers;
        await db.collection('messages').updateOne({ _id: toObjectId(messageId) }, { $set: { [`reactions.${trimmedReaction}`]: updatedUsers } });
      }

      const chatId = ensureChatIdString(message.chatId);
      safeEmit(io, `chat:${chatId}`, 'reaction:update', buildSocketEvent('reaction:update', { messageId, reactions }, { chatId, userId: req.userId }));
      successResponse(res, { messageId, reactions });
    } catch (err) {
      console.error('[POST /api/reactions] Error:', err.message);
      errorResponse(res, 500, 'Failed to update reaction', 'REACTION_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 11f: ADMIN ROUTES
  // ==========================================================================

  app.get('/api/admin/forgot-password-requests', auth, requireAdmin, async (req, res) => {
    try {
      const status = req.query?.status;
      const filter = {};
      if (status === 'pending' || status === 'resolved') filter.status = status;
      const limit = Math.min(parseInt(req.query?.limit, 10) || CONFIG.pagination.defaultLimit, CONFIG.pagination.maxLimit);
      const docs = await db.collection('forgotPasswordRequests').find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
      const requests = docs.map((d) => ({ id: String(d._id), username: d.username, whatsapp: d.whatsapp, status: d.status, createdAt: d.createdAt instanceof Date ? d.createdAt.toISOString() : d.createdAt, resolvedAt: d.resolvedAt instanceof Date ? d.resolvedAt.toISOString() : d.resolvedAt || null, resolvedBy: d.resolvedBy || null }));
      successResponse(res, { requests, total: requests.length });
    } catch (err) {
      console.error('[GET /api/admin/forgot-password-requests] Error:', err.message);
      errorResponse(res, 500, 'Failed to fetch requests', 'ADMIN_FETCH_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 11g: NOTIFICATIONS
  // ==========================================================================

  app.post('/api/notifications/subscribe', auth, async (req, res) => {
    try {
      const { subscription, deviceId } = req.body;
      if (!subscription || !subscription.endpoint || !subscription.keys) {
        return errorResponse(res, 400, 'Invalid subscription object', 'INVALID_SUBSCRIPTION');
      }

      const query = { userId: req.userId };
      if (deviceId) query.deviceId = deviceId;
      else query.subscription = subscription;

      await db.collection('pushSubscriptions').updateOne(
        query,
        { $set: { userId: req.userId, subscription, deviceId: deviceId || null, updatedAt: new Date().toISOString() } },
        { upsert: true }
      );

      successResponse(res, { success: true });
    } catch (err) {
      console.error('[POST /api/notifications/subscribe] Error:', err.message);
      errorResponse(res, 500, 'Failed to subscribe', 'SUBSCRIBE_ERROR');
    }
  });

  app.patch('/api/admin/forgot-password-requests/:id', auth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      if (!isValidObjectId(id)) return errorResponse(res, 400, 'Invalid request id', 'INVALID_ID');
      const result = await db.collection('forgotPasswordRequests').findOneAndUpdate(
        { _id: toObjectId(id) },
        { $set: { status: 'resolved', resolvedAt: new Date(), resolvedBy: req.user.id } },
        { returnDocument: 'after' }
      );
      const doc = result?.value || result;
      if (!doc || !doc._id) return errorResponse(res, 404, 'Request not found', 'NOT_FOUND');
      successResponse(res, { request: { id: String(doc._id), username: doc.username, whatsapp: doc.whatsapp, status: doc.status, createdAt: doc.createdAt instanceof Date ? doc.createdAt.toISOString() : doc.createdAt, resolvedAt: doc.resolvedAt instanceof Date ? doc.resolvedAt.toISOString() : doc.resolvedAt, resolvedBy: doc.resolvedBy || null } });
    } catch (err) {
      console.error('[PATCH /api/admin/forgot-password-requests/:id] Error:', err.message);
      errorResponse(res, 500, 'Failed to update request', 'ADMIN_UPDATE_ERROR');
    }
  });

  app.get('/api/admin/users', auth, requireAdmin, async (req, res) => {
    try {
      const filter = {};
      const q = sanitizeText(req.query?.q || '', 100);
      if (q) {
        const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        filter.$or = [{ username: new RegExp(escaped, 'i') }, { displayName: new RegExp(escaped, 'i') }];
      }
      if (req.query?.role === 'admin') filter.isAdmin = true;
      else if (req.query?.role === 'guest') filter.isGuest = true;
      else if (req.query?.role === 'user') { filter.isAdmin = { $ne: true }; filter.isGuest = { $ne: true }; }
      const limit = Math.min(parseInt(req.query?.limit, 10) || CONFIG.pagination.defaultLimit, CONFIG.pagination.maxLimit);
      const skip = Math.max(parseInt(req.query?.skip, 10) || 0, 0);
      const users = await db.collection('users').find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray();
      successResponse(res, { users: users.map(normalizeUser), total: users.length });
    } catch (err) {
      console.error('[GET /api/admin/users] Error:', err.message);
      errorResponse(res, 500, 'Failed to fetch users', 'ADMIN_FETCH_ERROR');
    }
  });

  app.patch('/api/admin/users/:id/role', auth, requireAdmin, async (req, res) => {
    try {
      const { id } = req.params;
      if (!isValidObjectId(id)) return errorResponse(res, 400, 'Invalid user id', 'INVALID_ID');
      const update = {};
      if (typeof req.body?.isAdmin === 'boolean') update.isAdmin = req.body.isAdmin;
      if (Object.keys(update).length === 0) return errorResponse(res, 400, 'No valid fields to update', 'NO_FIELDS');
      const result = await db.collection('users').updateOne({ _id: toObjectId(id) }, { $set: update });
      if (result.matchedCount === 0) return errorResponse(res, 404, 'User not found', 'USER_NOT_FOUND');
      invalidateUserCache(id);
      successResponse(res, { updated: true, fields: update });
    } catch (err) {
      console.error('[PATCH /api/admin/users/:id/role] Error:', err.message);
      errorResponse(res, 500, 'Failed to update role', 'ADMIN_UPDATE_ERROR');
    }
  });

  // ==========================================================================
  // SECTION 12: SOCKET.IO
  // ==========================================================================

  io.use(async (socket, next) => {
    try {
      const token = socket.handshake.auth?.token;
      if (!token) return next(new Error('AUTH_REQUIRED'));
      const session = await db.collection('sessions').findOne({ token }, { projection: { userId: 1 } });
      if (!session) return next(new Error('SESSION_EXPIRED'));
      const user = await getCachedUser(db, String(session.userId));
      if (!user) return next(new Error('USER_NOT_FOUND'));
      socket.userId = user.id;
      socket.username = user.username || user.displayName;
      next();
    } catch (err) {
      console.error('[Socket Auth] Error:', err.message);
      next(new Error('AUTH_ERROR'));
    }
  });

  io.on('connection', async (socket) => {
    const { userId, username } = socket;
    console.log(`[Socket] Connected: ${username} (${userId}) — ${socket.id}`);

    socket.join(`user:${userId}`);

    try {
      const chats = await db.collection('chats').find({ participants: userId }, { projection: { _id: 1, participants: 1 } }).toArray();
      for (const chat of chats) {
        socket.join(`chat:${ensureChatIdString(chat._id)}`);
      }
      const friendIds = [...new Set(chats.flatMap((c) => c.participants).filter((id) => id !== userId))];
      for (const fid of friendIds) socket.join(`user:${fid}:friends`);
    } catch (err) {
      console.error('[Socket] Room join error:', err.message);
    }

    setUserOnline(io, db, userId, socket.id);

    socket.on('join-chat', (data) => {
      try {
        const chatId = ensureChatIdString(data?.chatId);
        if (chatId) socket.join(`chat:${chatId}`);
      } catch {}
    });

    socket.on('leave-chat', (data) => {
      try {
        const chatId = ensureChatIdString(data?.chatId);
        if (chatId) socket.leave(`chat:${chatId}`);
      } catch {}
    });

    socket.on('typing:start', (data) => {
      try {
        const chatId = ensureChatIdString(data?.chatId);
        if (chatId) handleTypingStart(socket, io, db, chatId, userId, username);
      } catch {}
    });

    socket.on('typing:stop', (data) => {
      try {
        const chatId = ensureChatIdString(data?.chatId);
        if (chatId) handleTypingStop(socket, io, db, chatId, userId, username);
      } catch {}
    });

    // --- WebRTC Signaling ---
    socket.on('call:invite', async (data) => {
      if (data?.targetId) {
        // Track the caller
        activeCalls.set(socket.id, { callId: data.callId, otherId: data.targetId, role: 'caller' });
        
        socket.to(`user:${data.targetId}`).emit('call:invite', { ...data, callerId: userId });
        
        // Push notification for call
        sendPushNotification(db, data.targetId, {
          title: `Incoming ${data.isVideo ? 'Video' : 'Voice'} Call`,
          body: `${username} is calling you...`,
          tag: `call_${data.callId}`,
          data: { type: 'call', callId: data.callId, callerId: userId }
        });
      } else if (data?.chatId) {
        socket.to(`chat:${data.chatId}`).emit('call:invite', { ...data, callerId: userId });
      }
    });

    socket.on('call:accepted', (data) => {
      if (data?.targetId) {
        // Track the recipient too (targetId here is the caller)
        activeCalls.set(socket.id, { callId: data.callId, otherId: data.targetId, role: 'recipient' });
        socket.to(`user:${data.targetId}`).emit('call:accepted', { ...data, responderId: userId });
      }
    });

    socket.on('call:rejected', (data) => {
      if (data?.targetId) {
        // Cleanup the call for both participants
        for (const [sid, call] of activeCalls.entries()) {
          if (call.callId === data.callId) activeCalls.delete(sid);
        }
        socket.to(`user:${data.targetId}`).emit('call:rejected', { ...data, responderId: userId });
      }
    });

    socket.on('call:ice-candidate', (data) => {
      if (data?.targetId) {
        socket.to(`user:${data.targetId}`).emit('call:ice-candidate', { ...data, senderId: userId });
      }
    });

    socket.on('call:ended', (data) => {
      const callData = activeCalls.get(socket.id);
      const callIdToRemove = data.callId || callData?.callId;
      
      // Cleanup both sides from the Map
      if (callIdToRemove) {
        for (const [sid, call] of activeCalls.entries()) {
          if (call.callId === callIdToRemove) activeCalls.delete(sid);
        }
      }

      if (data?.targetId) {
        socket.to(`user:${data.targetId}`).emit('call:ended', { ...data, enderId: userId });
      } else if (data?.chatId) {
        socket.to(`chat:${data.chatId}`).emit('call:ended', { ...data, enderId: userId });
      }
    });
    // -------------------------

    socket.on('message:read', async (data) => {
      try {
        const chatId = ensureChatIdString(data?.chatId);
        if (!chatId) return;
        await db.collection('chatReads').updateOne({ chatId, userId }, { $set: { lastReadAt: new Date().toISOString() } }, { upsert: true });
      } catch {}
    });

    socket.on('rejoin', async () => {
      try {
        const chats = await db.collection('chats').find({ participants: userId }, { projection: { _id: 1 } }).toArray();
        for (const chat of chats) socket.join(`chat:${ensureChatIdString(chat._id)}`);
        socket.join(`user:${userId}`);
      } catch {}
    });

    socket.on('disconnect', (reason) => {
      console.log(`[Socket] Disconnected: ${username} (${userId}) — ${reason}`);
      
      // Auto-end WebRTC call if exists
      if (activeCalls.has(socket.id)) {
        const { callId, otherId } = activeCalls.get(socket.id);
        socket.to(`user:${otherId}`).emit('call:ended', { callId, enderId: userId, reason: 'disconnected' });
        
        // Cleanup all Map entries related to this callId
        for (const [sid, call] of activeCalls.entries()) {
          if (call.callId === callId) activeCalls.delete(sid);
        }
      }

      setUserOffline(io, db, userId, socket.id);
      for (const [key] of typingState) {
        if (key.endsWith(`:${userId}`)) {
          const [chatId] = key.split(':');
          handleTypingStop(io, db, chatId, userId, username);
        }
      }
    });
  });

  // ==========================================================================
  // SECTION 13: ERROR HANDLERS
  // ==========================================================================

  app.use((err, req, res, _next) => {
    console.error('[Global Error]', err.message);
    errorResponse(res, 500, 'Internal server error', 'INTERNAL_ERROR');
  });

  app.use((req, res) => {
    errorResponse(res, 404, 'Route not found', 'NOT_FOUND');
  });

  // ==========================================================================
  // SECTION 14: SERVER START
  // ==========================================================================

  httpServer.listen(CONFIG.port, () => {
    console.log(`
+-----------------------------------------------------+
|           ChatFlow API v2 is Running                |
+-----------------------------------------------------+
|  HTTP  ->  http://localhost:${CONFIG.port}                  |
|  WS    ->  ws://localhost:${CONFIG.port}                    |
|  DB    ->  ${CONFIG.dbName.padEnd(39)}|
|  CORS  ->  ${CONFIG.cors.origin.padEnd(39)}|
+-----------------------------------------------------+
    `);
  });

  const shutdown = async () => {
    console.log('[ChatFlow] Shutting down...');
    io.close();
    await mongoClient.close();
    process.exit(0);
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

startServer().catch((err) => {
  console.error('[FATAL] Startup Error:', err.message);
  process.exit(1);
});
