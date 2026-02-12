/// <reference lib="deno.ns" />

import {
  extname,
  fromFileUrl,
  join,
  relative,
} from "https://deno.land/std@0.210.0/path/mod.ts";
import { DatabaseSync } from "node:sqlite";

interface ConnectedUser {
  socketId: string;
  accountId: string;
  username: string;
  avatar: string;
  socket: WebSocket;
  currentRoom: string;
  isAdmin: boolean;
}

interface ChatMessage {
  id: string;
  userId: string; // Stable account ID
  username: string;
  avatar: string;
  content: string; // Encrypted on client
  timestamp: number;
  replyToId?: string;
  isSpoiler?: boolean;
  ttl?: number; // Time to live in milliseconds
}

interface AccountRecord {
  id: string;
  username: string;
  avatar: string;
  pinSalt: string;
  pinHash: string;
  isAdmin: boolean;
  createdAt: number;
}

interface SessionData {
  token: string;
  accountId: string;
  username: string;
  avatar: string;
  isAdmin: boolean;
  issuedAt: number;
}

interface PublicUser {
  id: string;
  username: string;
  avatar: string;
}

const DEFAULT_ROOM = "General";
const ROOT_ADMIN_USERNAME = "root";
const ROOT_ADMIN_DEFAULT_PIN = "0000";
const MAX_HISTORY_PER_ROOM = 400;

const users = new Map<string, ConnectedUser>();
const accountSockets = new Map<string, Set<string>>();
const sessions = new Map<string, SessionData>();
const rooms = new Set<string>([DEFAULT_ROOM]);
const messageHistory = new Map<string, ChatMessage[]>();

const moduleDir = fromFileUrl(new URL(".", import.meta.url));
const embeddedFrontendRoot = join(moduleDir, "..", "frontend");
const runtimeFrontendRoot = join(Deno.cwd(), "frontend");
const dbDir = join(Deno.cwd(), "backend");
const uploadDir = join(Deno.cwd(), "frontend", "static", "uploads");

Deno.mkdirSync(dbDir, { recursive: true });
Deno.mkdirSync(uploadDir, { recursive: true });

const dbPath = join(dbDir, "chat.sqlite3");
const db = new DatabaseSync(dbPath);

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  avatar TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  pin_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
`);

function toBase64(data: Uint8Array): string {
  return btoa(String.fromCharCode(...Array.from(data)));
}

function fromBase64(base64: string): Uint8Array {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function normalizeUsername(username: string): string {
  return username.trim();
}

function isValidUsername(username: string): boolean {
  return /^[a-zA-Z0-9_.-]{3,24}$/.test(username);
}

function isValidPin(pin: string): boolean {
  return /^\d{4,12}$/.test(pin);
}

function sanitizeAvatar(username: string, avatarInput?: string): string {
  const candidate = avatarInput?.trim();
  if (!candidate) {
    return `https://api.dicebear.com/7.x/avataaars/svg?seed=${
      encodeURIComponent(username)
    }`;
  }
  if (candidate.length > 1024) {
    return `https://api.dicebear.com/7.x/avataaars/svg?seed=${
      encodeURIComponent(username)
    }`;
  }
  return candidate;
}

async function hashPin(pin: string, saltBase64: string): Promise<string> {
  const encoder = new TextEncoder();
  const saltBytes = Uint8Array.from(fromBase64(saltBase64));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pin),
    { name: "PBKDF2" },
    false,
    ["deriveBits"],
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 180_000,
      hash: "SHA-256",
    },
    keyMaterial,
    256,
  );

  return toBase64(new Uint8Array(derivedBits));
}

function rowToAccount(row: any): AccountRecord {
  return {
    id: row.id,
    username: row.username,
    avatar: row.avatar,
    pinSalt: row.pin_salt,
    pinHash: row.pin_hash,
    isAdmin: Number(row.is_admin) === 1,
    createdAt: Number(row.created_at),
  };
}

function getUserByUsername(username: string): AccountRecord | null {
  const row = db.prepare(`
    SELECT id, username, avatar, pin_salt, pin_hash, is_admin, created_at
    FROM users
    WHERE username = ? COLLATE NOCASE
    LIMIT 1
  `).get(username) as any;
  return row ? rowToAccount(row) : null;
}

function getUserById(accountId: string): AccountRecord | null {
  const row = db.prepare(`
    SELECT id, username, avatar, pin_salt, pin_hash, is_admin, created_at
    FROM users
    WHERE id = ?
    LIMIT 1
  `).get(accountId) as any;
  return row ? rowToAccount(row) : null;
}

function listAllUsers(): AccountRecord[] {
  const rows = db.prepare(`
    SELECT id, username, avatar, pin_salt, pin_hash, is_admin, created_at
    FROM users
    ORDER BY is_admin DESC, created_at DESC
  `).all() as any[];
  return rows.map(rowToAccount);
}

function insertUser(user: AccountRecord) {
  db.prepare(`
    INSERT INTO users (id, username, avatar, pin_salt, pin_hash, is_admin, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    user.id,
    user.username,
    user.avatar,
    user.pinSalt,
    user.pinHash,
    user.isAdmin ? 1 : 0,
    user.createdAt,
  );
}

function updateUser(
  accountId: string,
  updates: {
    username?: string;
    avatar?: string;
    pinSalt?: string;
    pinHash?: string;
  },
) {
  const fields: string[] = [];
  const params: any[] = [];

  if (updates.username !== undefined) {
    fields.push("username = ?");
    params.push(updates.username);
  }
  if (updates.avatar !== undefined) {
    fields.push("avatar = ?");
    params.push(updates.avatar);
  }
  if (updates.pinSalt !== undefined) {
    fields.push("pin_salt = ?");
    params.push(updates.pinSalt);
  }
  if (updates.pinHash !== undefined) {
    fields.push("pin_hash = ?");
    params.push(updates.pinHash);
  }

  if (fields.length === 0) return;

  params.push(accountId);
  db.prepare(`UPDATE users SET ${fields.join(", ")} WHERE id = ?`).run(
    ...params,
  );
}

function updateUserAvatar(accountId: string, avatar: string) {
  updateUser(accountId, { avatar });
}

function deleteUser(accountId: string) {
  db.prepare("DELETE FROM users WHERE id = ?").run(accountId);
}

async function ensureRootAdmin() {
  const existing = getUserByUsername(ROOT_ADMIN_USERNAME);
  if (existing) return;

  const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  const pinHash = await hashPin(ROOT_ADMIN_DEFAULT_PIN, salt);
  const root: AccountRecord = {
    id: crypto.randomUUID(),
    username: ROOT_ADMIN_USERNAME,
    avatar: sanitizeAvatar(ROOT_ADMIN_USERNAME, ""),
    pinSalt: salt,
    pinHash,
    isAdmin: true,
    createdAt: Date.now(),
  };

  insertUser(root);
  console.log(
    `Root admin created: username="${ROOT_ADMIN_USERNAME}", pin="${ROOT_ADMIN_DEFAULT_PIN}"`,
  );
}

function createSession(user: AccountRecord): SessionData {
  const token = crypto.randomUUID();
  const session: SessionData = {
    token,
    accountId: user.id,
    username: user.username,
    avatar: user.avatar,
    isAdmin: user.isAdmin,
    issuedAt: Date.now(),
  };
  sessions.set(token, session);
  return session;
}

function removeSessionsForAccount(accountId: string) {
  for (const [token, session] of sessions.entries()) {
    if (session.accountId === accountId) {
      sessions.delete(token);
    }
  }
}

function readBearerToken(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (!authHeader) return null;
  const [scheme, token] = authHeader.split(" ");
  if (!scheme || !token || scheme.toLowerCase() !== "bearer") return null;
  return token.trim();
}

function getSessionFromRequest(req: Request): SessionData | null {
  const token = readBearerToken(req);
  if (!token) return null;
  return sessions.get(token) ?? null;
}

function jsonResponse(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

async function parseJsonBody(req: Request): Promise<Record<string, unknown>> {
  try {
    return await req.json() as Record<string, unknown>;
  } catch {
    return {};
  }
}

function getOnlineAccountIds(): Set<string> {
  return new Set(Array.from(users.values()).map((user) => user.accountId));
}

function buildPublicUserList(roomId: string): PublicUser[] {
  const uniqueUsers = new Map<string, PublicUser>();
  for (const user of users.values()) {
    if (user.currentRoom !== roomId) continue;
    if (!uniqueUsers.has(user.accountId)) {
      uniqueUsers.set(user.accountId, {
        id: user.accountId,
        username: user.username,
        avatar: user.avatar,
      });
    }
  }
  return Array.from(uniqueUsers.values());
}

function broadcast(roomId: string, data: unknown) {
  const payload = JSON.stringify(data);
  for (const user of users.values()) {
    if (
      user.currentRoom === roomId && user.socket.readyState === WebSocket.OPEN
    ) {
      user.socket.send(payload);
    }
  }
}

function broadcastRoomList() {
  const payload = JSON.stringify({
    type: "room_list",
    rooms: Array.from(rooms),
  });
  for (const user of users.values()) {
    if (user.socket.readyState === WebSocket.OPEN) {
      user.socket.send(payload);
    }
  }
}

function broadcastUserList(roomId: string) {
  broadcast(roomId, { type: "user_list", users: buildPublicUserList(roomId) });
}

function attachSocketToAccount(accountId: string, socketId: string) {
  const set = accountSockets.get(accountId) ?? new Set<string>();
  set.add(socketId);
  accountSockets.set(accountId, set);
}

function detachSocketFromAccount(accountId: string, socketId: string) {
  const set = accountSockets.get(accountId);
  if (!set) return;
  set.delete(socketId);
  if (set.size === 0) {
    accountSockets.delete(accountId);
  }
}

function removeMessagesByAccount(accountId: string): number {
  let removed = 0;
  for (const [roomId, history] of messageHistory.entries()) {
    const filtered = history.filter((msg) => msg.userId !== accountId);
    removed += history.length - filtered.length;
    messageHistory.set(roomId, filtered);
  }
  return removed;
}

function disconnectAccount(accountId: string, reason: string) {
  const socketIds = Array.from(accountSockets.get(accountId) ?? []);
  for (const socketId of socketIds) {
    const user = users.get(socketId);
    if (!user) continue;
    if (user.socket.readyState === WebSocket.OPEN) {
      user.socket.send(
        JSON.stringify({
          type: "account_deleted",
          payload: { message: reason },
        }),
      );
      user.socket.close(4001, reason);
    }
  }
}

function deleteUserAndData(accountId: string): { removedMessages: number } {
  const removedMessages = removeMessagesByAccount(accountId);
  removeSessionsForAccount(accountId);
  disconnectAccount(accountId, "Your account was deleted by an admin.");
  deleteUser(accountId);
  return { removedMessages };
}

function wipeNonAdminData(): { removedUsers: number } {
  const allUsers = listAllUsers();
  const nonAdmins = allUsers.filter((user) => !user.isAdmin);

  for (const user of nonAdmins) {
    removeSessionsForAccount(user.id);
    disconnectAccount(user.id, "Your account was removed during admin reset.");
    deleteUser(user.id);
  }

  messageHistory.clear();
  rooms.clear();
  rooms.add(DEFAULT_ROOM);

  for (const user of users.values()) {
    if (user.currentRoom !== DEFAULT_ROOM) {
      user.currentRoom = DEFAULT_ROOM;
      user.socket.send(JSON.stringify({ type: "history", messages: [] }));
    }
  }

  broadcastRoomList();
  broadcastUserList(DEFAULT_ROOM);
  return { removedUsers: nonAdmins.length };
}

function getContentType(path: string): string {
  const extension = extname(path).toLowerCase();

  switch (extension) {
    case ".html":
      return "text/html; charset=utf-8";
    case ".css":
      return "text/css; charset=utf-8";
    case ".js":
    case ".mjs":
      return "application/javascript; charset=utf-8";
    case ".json":
      return "application/json; charset=utf-8";
    case ".txt":
      return "text/plain; charset=utf-8";
    case ".map":
      return "application/json; charset=utf-8";
    case ".pdf":
      return "application/pdf";
    case ".svg":
      return "image/svg+xml";
    case ".png":
      return "image/png";
    case ".jpg":
    case ".jpeg":
      return "image/jpeg";
    case ".gif":
      return "image/gif";
    case ".bmp":
      return "image/bmp";
    case ".avif":
      return "image/avif";
    case ".ico":
      return "image/x-icon";
    case ".heic":
      return "image/heic";
    case ".heif":
      return "image/heif";
    case ".webp":
      return "image/webp";
    case ".mp3":
      return "audio/mpeg";
    case ".wav":
      return "audio/wav";
    case ".ogg":
      return "audio/ogg";
    case ".m4a":
      return "audio/mp4";
    case ".aac":
      return "audio/aac";
    case ".flac":
      return "audio/flac";
    case ".opus":
      return "audio/opus";
    case ".weba":
      return "audio/webm";
    case ".mp4":
      return "video/mp4";
    case ".webm":
      return "video/webm";
    case ".mov":
      return "video/quicktime";
    case ".m4v":
      return "video/x-m4v";
    case ".mpeg":
    case ".mpg":
      return "video/mpeg";
    case ".zip":
      return "application/zip";
    case ".gz":
      return "application/gzip";
    case ".tar":
      return "application/x-tar";
    case ".7z":
      return "application/x-7z-compressed";
    case ".rar":
      return "application/vnd.rar";
    case ".woff":
      return "font/woff";
    case ".woff2":
      return "font/woff2";
    case ".ttf":
      return "font/ttf";
    case ".otf":
      return "font/otf";
    default:
      return "application/octet-stream";
  }
}

function resolveSafePath(baseDir: string, requestPath: string): string | null {
  const cleaned = requestPath.replace(/^\/+/, "");
  if (!cleaned || cleaned.includes("\0")) return null;
  const fullPath = join(baseDir, cleaned);
  const rel = relative(baseDir, fullPath);
  if (rel.startsWith("..")) return null;
  return fullPath;
}

async function readFrontendAsset(path: string): Promise<Uint8Array | null> {
  const roots = [embeddedFrontendRoot, runtimeFrontendRoot];

  for (const root of roots) {
    const fullPath = resolveSafePath(root, path);
    if (!fullPath) continue;
    try {
      return await Deno.readFile(fullPath);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) continue;
      throw error;
    }
  }

  return null;
}

async function handleSignup(req: Request): Promise<Response> {
  const body = await parseJsonBody(req);
  const username = normalizeUsername(String(body.username ?? ""));
  const pin = String(body.pin ?? "");
  const avatarInput = String(body.avatar ?? "");

  if (!isValidUsername(username)) {
    return jsonResponse(400, {
      error: "Username must be 3-24 chars and only letters, numbers, _, -, .",
    });
  }
  if (!isValidPin(pin)) {
    return jsonResponse(400, { error: "PIN must be numeric and 4-12 digits." });
  }
  if (getUserByUsername(username)) {
    return jsonResponse(409, { error: "Username is already taken." });
  }

  const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
  const pinHash = await hashPin(pin, salt);
  const user: AccountRecord = {
    id: crypto.randomUUID(),
    username,
    avatar: sanitizeAvatar(username, avatarInput),
    pinSalt: salt,
    pinHash,
    isAdmin: false,
    createdAt: Date.now(),
  };

  insertUser(user);
  const session = createSession(user);

  return jsonResponse(201, {
    token: session.token,
    user: {
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      isAdmin: user.isAdmin,
    },
  });
}

async function handleLogin(req: Request): Promise<Response> {
  const body = await parseJsonBody(req);
  const username = normalizeUsername(String(body.username ?? ""));
  const pin = String(body.pin ?? "");
  const avatarInput = String(body.avatar ?? "");

  const user = getUserByUsername(username);
  if (!user) {
    return jsonResponse(401, { error: "Invalid username or PIN." });
  }

  const expectedHash = await hashPin(pin, user.pinSalt);
  if (expectedHash !== user.pinHash) {
    return jsonResponse(401, { error: "Invalid username or PIN." });
  }

  const updatedAvatar = sanitizeAvatar(user.username, avatarInput);
  if (updatedAvatar !== user.avatar) {
    user.avatar = updatedAvatar;
    updateUserAvatar(user.id, updatedAvatar);
  }

  const session = createSession(user);
  return jsonResponse(200, {
    token: session.token,
    user: {
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      isAdmin: user.isAdmin,
    },
  });
}

function handleLogout(req: Request): Response {
  const token = readBearerToken(req);
  if (token) sessions.delete(token);
  return jsonResponse(200, { ok: true });
}

function handleAdminUsers(req: Request): Response {
  const session = getSessionFromRequest(req);
  if (!session || !session.isAdmin) {
    return jsonResponse(403, { error: "Admin access required." });
  }

  const onlineUsers = getOnlineAccountIds();
  const allUsers = listAllUsers();

  return jsonResponse(200, {
    users: allUsers.map((user) => ({
      id: user.id,
      username: user.username,
      avatar: user.avatar,
      isAdmin: user.isAdmin,
      createdAt: user.createdAt,
      isOnline: onlineUsers.has(user.id),
    })),
  });
}

async function handleAdminDeleteUser(req: Request): Promise<Response> {
  const session = getSessionFromRequest(req);
  if (!session || !session.isAdmin) {
    return jsonResponse(403, { error: "Admin access required." });
  }

  const body = await parseJsonBody(req);
  const targetId = String(body.userId ?? "");
  const targetUsername = normalizeUsername(String(body.username ?? ""));

  let target = targetId ? getUserById(targetId) : null;
  if (!target && targetUsername) {
    target = getUserByUsername(targetUsername);
  }

  if (!target) {
    return jsonResponse(404, { error: "User not found." });
  }
  if (target.isAdmin) {
    return jsonResponse(400, { error: "Admin users cannot be deleted." });
  }
  if (target.id === session.accountId) {
    return jsonResponse(400, { error: "You cannot delete your own account." });
  }

  const result = deleteUserAndData(target.id);
  broadcastRoomList();
  for (const roomId of rooms) {
    broadcastUserList(roomId);
  }

  return jsonResponse(200, {
    ok: true,
    deletedUserId: target.id,
    removedMessages: result.removedMessages,
  });
}

function handleAdminWipe(req: Request): Response {
  const session = getSessionFromRequest(req);
  if (!session || !session.isAdmin) {
    return jsonResponse(403, { error: "Admin access required." });
  }

  const result = wipeNonAdminData();
  return jsonResponse(200, {
    ok: true,
    removedUsers: result.removedUsers,
    removedMessages: "all room history cleared",
  });
}

async function handleUpdateProfile(req: Request): Promise<Response> {
  const session = getSessionFromRequest(req);
  if (!session) {
    return jsonResponse(401, { error: "Authentication required." });
  }

  const body = await parseJsonBody(req);
  const newUsername = body.username
    ? normalizeUsername(String(body.username))
    : undefined;
  const newPin = body.pin ? String(body.pin) : undefined;
  const avatarInput = body.avatar !== undefined
    ? String(body.avatar)
    : undefined;

  const user = getUserById(session.accountId);
  if (!user) {
    return jsonResponse(404, { error: "User not found." });
  }

  const updates: any = {};

  if (newUsername !== undefined && newUsername !== user.username) {
    if (!isValidUsername(newUsername)) {
      return jsonResponse(400, { error: "Invalid username format." });
    }
    if (getUserByUsername(newUsername)) {
      return jsonResponse(409, { error: "Username is already taken." });
    }
    updates.username = newUsername;
    session.username = newUsername;
  }

  if (avatarInput !== undefined) {
    const updatedAvatar = sanitizeAvatar(
      newUsername ?? user.username,
      avatarInput,
    );
    if (updatedAvatar !== user.avatar) {
      updates.avatar = updatedAvatar;
      session.avatar = updatedAvatar;
    }
  }

  if (newPin !== undefined) {
    if (!isValidPin(newPin)) {
      return jsonResponse(400, {
        error: "PIN must be numeric and 4-12 digits.",
      });
    }
    const salt = toBase64(crypto.getRandomValues(new Uint8Array(16)));
    const pinHash = await hashPin(newPin, salt);
    updates.pinSalt = salt;
    updates.pinHash = pinHash;
  }

  if (Object.keys(updates).length > 0) {
    updateUser(user.id, updates);

    // Update connected users in memory
    for (const u of users.values()) {
      if (u.accountId === user.id) {
        if (updates.username) u.username = updates.username;
        if (updates.avatar) u.avatar = updates.avatar;

        // Notify the client about info change
        u.socket.send(JSON.stringify({
          type: "session_info",
          payload: {
            userId: u.accountId,
            username: u.username,
            avatar: u.avatar,
            isAdmin: u.isAdmin,
          },
        }));
      }
    }

    // Broadcast user list update to all rooms the user is in
    for (const roomId of rooms) {
      broadcastUserList(roomId);
    }
  }

  return jsonResponse(200, {
    ok: true,
    user: {
      id: user.id,
      username: session.username,
      avatar: session.avatar,
      isAdmin: user.isAdmin,
    },
  });
}

async function handleUpload(req: Request): Promise<Response> {
  const session = getSessionFromRequest(req);
  if (!session) return jsonResponse(401, { error: "Authentication required." });

  const formData = await req.formData();
  const file = formData.get("file") as File;
  if (!file) return jsonResponse(400, { error: "No file provided." });

  const ext = extname(file.name);
  const fileName = `${crypto.randomUUID()}${ext}`;

  const arrayBuffer = await file.arrayBuffer();
  await Deno.writeFile(join(uploadDir, fileName), new Uint8Array(arrayBuffer));

  const url = `/static/uploads/${fileName}`;
  return jsonResponse(200, { url, fileName: file.name });
}

async function handleApi(req: Request, pathname: string): Promise<Response> {
  if (req.method === "POST" && pathname === "/api/upload") {
    return await handleUpload(req);
  }
  if (req.method === "POST" && pathname === "/api/auth/signup") {
    return await handleSignup(req);
  }
  if (req.method === "POST" && pathname === "/api/auth/login") {
    return await handleLogin(req);
  }
  if (req.method === "POST" && pathname === "/api/auth/logout") {
    return handleLogout(req);
  }
  if (req.method === "GET" && pathname === "/api/admin/users") {
    return handleAdminUsers(req);
  }
  if (req.method === "POST" && pathname === "/api/admin/delete-user") {
    return await handleAdminDeleteUser(req);
  }
  if (req.method === "POST" && pathname === "/api/admin/wipe") {
    return handleAdminWipe(req);
  }
  if (req.method === "POST" && pathname === "/api/auth/update-profile") {
    return await handleUpdateProfile(req);
  }

  return jsonResponse(404, { error: "API route not found." });
}

function handleWebSocket(req: Request): Response {
  const { socket, response } = Deno.upgradeWebSocket(req);
  const socketId = crypto.randomUUID();

  socket.onopen = () => {
    console.log(`Socket opened: ${socketId}`);
  };

  socket.onmessage = (event: MessageEvent) => {
    let data: any;
    try {
      data = JSON.parse(event.data);
    } catch {
      socket.send(
        JSON.stringify({ type: "error", error: "Invalid message format." }),
      );
      return;
    }

    switch (data.type) {
      case "join": {
        const token = String(data.payload?.token ?? "");
        const roomId = String(data.payload?.roomId ?? DEFAULT_ROOM).trim() ||
          DEFAULT_ROOM;
        const session = sessions.get(token);

        if (!session) {
          socket.send(
            JSON.stringify({
              type: "error",
              error: "Authentication required.",
            }),
          );
          socket.close(4001, "Unauthorized");
          return;
        }

        const user: ConnectedUser = {
          socketId,
          accountId: session.accountId,
          username: session.username,
          avatar: session.avatar,
          socket,
          currentRoom: roomId,
          isAdmin: session.isAdmin,
        };

        users.set(socketId, user);
        attachSocketToAccount(user.accountId, socketId);

        if (!rooms.has(user.currentRoom)) {
          rooms.add(user.currentRoom);
        }

        const history = messageHistory.get(user.currentRoom) || [];
        socket.send(JSON.stringify({ type: "history", messages: history }));
        socket.send(JSON.stringify({
          type: "session_info",
          payload: {
            userId: user.accountId,
            username: user.username,
            avatar: user.avatar,
            isAdmin: user.isAdmin,
          },
        }));

        broadcastRoomList();
        broadcastUserList(user.currentRoom);
        break;
      }

      case "message": {
        const user = users.get(socketId);
        if (!user) return;

        const content = String(data.payload?.content ?? "").trim();

        if (content === "/clear") {
          const removed = removeMessagesByAccount(user.accountId);
          socket.send(JSON.stringify({
            type: "info",
            payload: { message: `Cleared ${removed} messages.` },
          }));
          // Broadcast to everyone in the room that history changed (or just let them see the deletions on next load)
          // To be immediate, we should broadcast a "clear_user_messages" event
          broadcast(user.currentRoom, {
            type: "clear_user_messages",
            payload: { userId: user.accountId },
          });
          break;
        }

        const message: ChatMessage = {
          id: crypto.randomUUID(),
          userId: user.accountId,
          username: user.username,
          avatar: user.avatar,
          content: content,
          timestamp: Date.now(),
          replyToId: data.payload?.replyToId,
          isSpoiler: data.payload?.isSpoiler,
          ttl: data.payload?.ttl,
        };

        const history = messageHistory.get(user.currentRoom) || [];
        history.push(message);
        if (history.length > MAX_HISTORY_PER_ROOM) history.shift();
        messageHistory.set(user.currentRoom, history);
        broadcast(user.currentRoom, { type: "message", message });

        if (message.ttl) {
          setTimeout(() => {
            const h = messageHistory.get(user.currentRoom) || [];
            const filtered = h.filter((m) => m.id !== message.id);
            messageHistory.set(user.currentRoom, filtered);
            broadcast(user.currentRoom, {
              type: "delete_message",
              payload: { messageId: message.id },
            });
          }, message.ttl);
        }
        break;
}

      case "create_room": {
        const user = users.get(socketId);
        if (!user) return;
        const roomName = String(data.payload?.roomName ?? "").trim();
        if (!roomName) return;
        rooms.add(roomName);
        broadcastRoomList();
        break;
      }

      case "switch_room": {
        const user = users.get(socketId);
        if (!user) return;
        const nextRoom = String(data.payload?.roomId ?? "").trim() ||
          DEFAULT_ROOM;
        const oldRoom = user.currentRoom;
        user.currentRoom = nextRoom;
        if (!rooms.has(nextRoom)) rooms.add(nextRoom);

        const history = messageHistory.get(nextRoom) || [];
        socket.send(JSON.stringify({ type: "history", messages: history }));
        broadcastUserList(oldRoom);
        broadcastUserList(nextRoom);
        broadcastRoomList();
        break;
      }
    }
  };

  socket.onclose = () => {
    const user = users.get(socketId);
    if (user) {
      users.delete(socketId);
      detachSocketFromAccount(user.accountId, socketId);
      broadcastUserList(user.currentRoom);
    }
    console.log(`Socket closed: ${socketId}`);
  };

  return response;
}

const handler = async (req: Request): Promise<Response> => {
  const url = new URL(req.url);

  if (req.headers.get("upgrade") === "websocket") {
    return handleWebSocket(req);
  }

  if (url.pathname.startsWith("/api/")) {
    return await handleApi(req, url.pathname);
  }

  const path = url.pathname === "/" ? "/index.html" : url.pathname;
  try {
    if (path.startsWith("/static/uploads/")) {
      const relativeUploadPath = path.slice("/static/uploads/".length);
      const fullUploadPath = resolveSafePath(uploadDir, relativeUploadPath);
      if (!fullUploadPath) {
        return new Response("Not Found", { status: 404 });
      }
      const file = await Deno.readFile(fullUploadPath);
      return new Response(file as unknown as BodyInit, {
        headers: { "content-type": getContentType(path) },
      });
    }

    const file = await readFrontendAsset(path);
    if (!file) {
      return new Response("Not Found", { status: 404 });
    }
    return new Response(file as unknown as BodyInit, {
      headers: { "content-type": getContentType(path) },
    });
  } catch {
    return new Response("Not Found", { status: 404 });
  }
};

await ensureRootAdmin();
console.log("Server running on http://localhost:8000");
Deno.serve({ port: 8000 }, handler);
