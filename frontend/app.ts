/// <reference lib="dom" />

type AuthMode = "login" | "signup";

interface UserInfo {
  id: string;
  username: string;
  avatar: string;
  roomId: string;
  isAdmin: boolean;
}

interface MessageData {
  id: string;
  userId: string;
  username: string;
  avatar: string;
  content: string;
  timestamp: number;
  replyToId?: string;
  isSpoiler?: boolean;
  ttl?: number;
}

interface RoomUser {
  id: string;
  username: string;
  avatar: string;
}

interface AdminUser {
  id: string;
  username: string;
  avatar: string;
  isAdmin: boolean;
  createdAt: number;
  isOnline: boolean;
}

interface SocketMessage {
  type:
    | "join"
    | "message"
    | "history"
    | "room_list"
    | "user_list"
    | "session_info"
    | "error"
    | "account_deleted";
  payload?: any;
  error?: string;
  messages?: MessageData[];
  message?: MessageData;
  rooms?: string[];
  users?: RoomUser[];
}

interface StoredProfile {
  username: string;
  avatar: string;
}

interface NotificationPreferences {
  soundEnabled: boolean;
  desktopEnabled: boolean;
  toastEnabled: boolean;
}

interface MutedUserRecord {
  id?: string;
  username: string;
  avatar: string;
}

interface AuthSuccess {
  token: string;
  user: {
    id: string;
    username: string;
    avatar: string;
    isAdmin: boolean;
  };
}

const DEFAULT_ROOM = "General";
const PROFILE_STORAGE_KEY = "lan-chat-profile";
const NOTIFICATION_STORAGE_KEY = "lan-chat-notification-preferences";
const MUTED_USERS_STORAGE_KEY = "lan-chat-muted-users";
const THEME_STORAGE_KEY = "selected-theme";
const MESSAGE_SOUND_PATH = "/static/sound/discord_message.mp3";

let socket: WebSocket | null = null;
let shouldReconnect = false;
let authMode: AuthMode = "login";
let authToken: string | null = null;

let currentUser: UserInfo = {
  id: "",
  username: "",
  avatar: "",
  roomId: DEFAULT_ROOM,
  isAdmin: false,
};
let currentRoom = DEFAULT_ROOM;
let replyToId: string | null = null;
let isSpoilerNext = false;
let currentTTL: number | null = null;
let encryptionKey: CryptoKey | null = null;
let unreadCount = 0;
let isFocused = true;
let activeUsers: RoomUser[] = [];
let activeAdminUsers: AdminUser[] = [];
let mentionQuery: string | null = null;
let selectedSuggestionIndex = 0;
const MENTION_REGEX = /(@[a-zA-Z0-9_.-]+)/g;

const mutedUsers = new Map<string, MutedUserRecord>();
const notificationPrefs: NotificationPreferences = {
  soundEnabled: true,
  desktopEnabled: true,
  toastEnabled: true,
};

const messageSound = new Audio(MESSAGE_SOUND_PATH);
messageSound.preload = "auto";
messageSound.volume = 0.45;

const msgContainer = document.getElementById("chat-messages") as HTMLDivElement;
const msgInput = document.getElementById(
  "message-input",
) as HTMLTextAreaElement;
const roomOnlineCountNode = document.getElementById("room-online-count") as
  | HTMLElement
  | null;
const appSidebar = document.getElementById("app-sidebar") as HTMLElement | null;
const sidebarToggleBtn = document.getElementById("sidebar-toggle-btn") as
  | HTMLButtonElement
  | null;
const MOBILE_BREAKPOINT_PX = 980;
const MEDIA_URL_REGEX = /((https?:\/\/[^\s<]+)|(\/static\/[^\s<]+))/g;
const IMAGE_EXTENSIONS = new Set([
  "jpg",
  "jpeg",
  "png",
  "gif",
  "webp",
  "svg",
  "bmp",
  "avif",
  "heic",
  "heif",
]);
const AUDIO_EXTENSIONS = new Set([
  "mp3",
  "wav",
  "ogg",
  "m4a",
  "aac",
  "flac",
  "opus",
  "weba",
]);

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function encodeInline(value: string): string {
  return encodeURIComponent(value);
}

function decodeInline(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function updateTitle() {
  document.title = unreadCount > 0 ? `(${unreadCount}) LAN Chat` : "LAN Chat";
}

function updateProfileCard() {
  (document.getElementById("my-username") as HTMLElement).innerText =
    currentUser.username || "guest";
  const statusLabel = document.getElementById("my-role") as HTMLElement;
  if (statusLabel) {
    statusLabel.innerText = currentUser.isAdmin ? "root admin" : "member";
  }
}

function setAdminPanelVisibility() {
  const panel = document.getElementById("admin-panel");
  if (!panel) return;
  panel.classList.toggle("hidden", !currentUser.isAdmin);
}

function isMobileLayout(): boolean {
  return window.innerWidth <= MOBILE_BREAKPOINT_PX;
}

function isSidebarOpen(): boolean {
  return document.body.classList.contains("sidebar-open");
}

function syncSidebarState() {
  const sidebarHidden = isMobileLayout() ? !isSidebarOpen() : false;
  if (appSidebar) {
    appSidebar.setAttribute("aria-hidden", sidebarHidden ? "true" : "false");
  }
  if (sidebarToggleBtn) {
    sidebarToggleBtn.setAttribute(
      "aria-expanded",
      isSidebarOpen() ? "true" : "false",
    );
  }
}

function setSidebarOpen(open: boolean) {
  const shouldOpen = open && isMobileLayout();
  document.body.classList.toggle("sidebar-open", shouldOpen);
  syncSidebarState();
}

function toggleSidebar() {
  setSidebarOpen(!isSidebarOpen());
}

function closeSidebar() {
  setSidebarOpen(false);
}

async function requestApi<T>(
  path: string,
  init: RequestInit = {},
  authRequired = false,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (!(init.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  const incomingHeaders = init.headers as Record<string, string> | undefined;
  if (incomingHeaders) {
    for (const [key, value] of Object.entries(incomingHeaders)) {
      headers[key] = value;
    }
  }
  if (authRequired && authToken) {
    headers.Authorization = `Bearer ${authToken}`;
  }

  const response = await fetch(path, { ...init, headers });
  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(
      (data as any).error || `Request failed (${response.status})`,
    );
  }
  return data as T;
}

function loadStoredProfile(): StoredProfile | null {
  try {
    const raw = localStorage.getItem(PROFILE_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as StoredProfile;
    if (!parsed.username) return null;
    return parsed;
  } catch {
    return null;
  }
}

function saveStoredProfile(profile: StoredProfile) {
  localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(profile));
}

function restoreProfileInputs() {
  const storedProfile = loadStoredProfile();
  if (!storedProfile) return;
  (document.getElementById("username-input") as HTMLInputElement).value =
    storedProfile.username;
  (document.getElementById("avatar-input") as HTMLInputElement).value =
    storedProfile.avatar || "";
}

function loadNotificationPreferences() {
  try {
    const raw = localStorage.getItem(NOTIFICATION_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as Partial<NotificationPreferences>;
    notificationPrefs.soundEnabled = typeof parsed.soundEnabled === "boolean"
      ? parsed.soundEnabled
      : true;
    notificationPrefs.desktopEnabled =
      typeof parsed.desktopEnabled === "boolean" ? parsed.desktopEnabled : true;
    notificationPrefs.toastEnabled = typeof parsed.toastEnabled === "boolean"
      ? parsed.toastEnabled
      : true;
  } catch {
    notificationPrefs.soundEnabled = true;
    notificationPrefs.desktopEnabled = true;
    notificationPrefs.toastEnabled = true;
  }

  if (!("Notification" in window)) {
    notificationPrefs.desktopEnabled = false;
  }
}

function saveNotificationPreferences() {
  localStorage.setItem(
    NOTIFICATION_STORAGE_KEY,
    JSON.stringify(notificationPrefs),
  );
}

function syncNotificationControls() {
  const soundToggle = document.getElementById(
    "sound-toggle",
  ) as HTMLInputElement;
  const desktopToggle = document.getElementById(
    "desktop-toggle",
  ) as HTMLInputElement;
  const toastToggle = document.getElementById(
    "toast-toggle",
  ) as HTMLInputElement;

  if (soundToggle) soundToggle.checked = notificationPrefs.soundEnabled;
  if (desktopToggle) desktopToggle.checked = notificationPrefs.desktopEnabled;
  if (toastToggle) toastToggle.checked = notificationPrefs.toastEnabled;

  if (desktopToggle && !("Notification" in window)) {
    desktopToggle.disabled = true;
    desktopToggle.title =
      "Desktop notifications are not supported in this browser.";
  }
}

function openProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (!modal) return;

  (document.getElementById("edit-username") as HTMLInputElement).value =
    currentUser.username;
  (document.getElementById("edit-avatar") as HTMLInputElement).value =
    currentUser.avatar;
  (document.getElementById("edit-pin") as HTMLInputElement).value = "";

  modal.classList.remove("hidden");
  modal.classList.add("flex");
}

function closeProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.classList.remove("flex");
}

async function saveProfile() {
  const username =
    (document.getElementById("edit-username") as HTMLInputElement).value;
  const avatar =
    (document.getElementById("edit-avatar") as HTMLInputElement).value;
  const pin = (document.getElementById("edit-pin") as HTMLInputElement).value;

  const saveBtn = document.querySelector(
    "#profile-modal .primary-btn span",
  ) as HTMLElement;
  const btnBox = document.querySelector(
    "#profile-modal .primary-btn",
  ) as HTMLButtonElement;
  if (!saveBtn || !btnBox) return;

  const originalText = saveBtn.innerText;
  btnBox.disabled = true;
  saveBtn.innerText = "SAVING...";

  try {
    const result = await requestApi<AuthSuccess>("/api/auth/update-profile", {
      method: "POST",
      body: JSON.stringify({
        username,
        avatar,
        pin: pin || undefined,
      }),
    }, true);

    currentUser.username = result.user.username;
    currentUser.avatar = result.user.avatar;

    saveStoredProfile({
      username: result.user.username,
      avatar: result.user.avatar,
    });

    showToast(`Profile updated!`, "success");
    updateProfileCard();
    closeProfileModal();
  } catch (err: any) {
    showToast(err.message, "error");
  } finally {
    btnBox.disabled = false;
    saveBtn.innerText = originalText;
  }
}

function getMuteKey(userId: string | undefined, username: string): string {
  return userId || normalizeUsername(username);
}

function loadMutedUsers() {
  try {
    const raw = localStorage.getItem(MUTED_USERS_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw) as { key: string; user: MutedUserRecord }[];
    for (const entry of parsed) {
      if (entry?.key && entry?.user?.username) {
        mutedUsers.set(entry.key, entry.user);
      }
    }
  } catch {
    mutedUsers.clear();
  }
}

function saveMutedUsers() {
  const entries = Array.from(mutedUsers.entries()).map(([key, user]) => ({
    key,
    user,
  }));
  localStorage.setItem(MUTED_USERS_STORAGE_KEY, JSON.stringify(entries));
}

function isUserMuted(userId: string | undefined, username: string): boolean {
  if (userId && mutedUsers.has(userId)) return true;
  const normalized = normalizeUsername(username);
  for (const mutedUser of mutedUsers.values()) {
    if (normalizeUsername(mutedUser.username) === normalized) return true;
  }
  return false;
}

function isMessageMuted(msg: MessageData): boolean {
  return isUserMuted(msg.userId, msg.username);
}

function muteUser(
  userId: string | undefined,
  username: string,
  avatar: string,
) {
  const key = getMuteKey(userId, username);
  mutedUsers.set(key, { id: userId, username, avatar });
  saveMutedUsers();
  renderMutedUsers();
}

function unmuteUser(userId: string | undefined, username: string) {
  if (userId) mutedUsers.delete(userId);
  const normalized = normalizeUsername(username);
  for (const [key, mutedUser] of mutedUsers.entries()) {
    if (normalizeUsername(mutedUser.username) === normalized) {
      mutedUsers.delete(key);
    }
  }
  saveMutedUsers();
  renderMutedUsers();
}

function renderMutedUsers() {
  const container = document.getElementById(
    "muted-user-list",
  ) as HTMLDivElement;
  const countNode = document.getElementById("muted-count") as HTMLElement;
  const users = Array.from(mutedUsers.values());
  countNode.innerText = users.length.toString();

  if (users.length === 0) {
    container.innerHTML =
      `<p class="text-[13px] text-[var(--text-muted)]">No muted people</p>`;
    return;
  }

  container.innerHTML = users.map((user) => {
    const userId = user.id || "";
    return `
            <div class="muted-user-row">
                <div class="flex items-center gap-2 min-w-0">
                    <span class="text-xs text-[var(--text-color)] truncate">${
      escapeHtml(user.username)
    }</span>
                </div>
                <button onclick="toggleUserMute('${encodeInline(userId)}','${
      encodeInline(user.username)
    }','${encodeInline(user.avatar)}')" class="mini-action-btn">unmute</button>
            </div>
        `;
  }).join("");
}

function setAuthMode(mode: AuthMode) {
  authMode = mode;
  const loginBtn = document.getElementById(
    "mode-login-btn",
  ) as HTMLButtonElement;
  const signupBtn = document.getElementById(
    "mode-signup-btn",
  ) as HTMLButtonElement;
  const submitLabel = document.getElementById(
    "auth-submit-label",
  ) as HTMLElement;
  const subtitle = document.getElementById("auth-subtitle") as HTMLElement;

  loginBtn.classList.toggle("is-active", mode === "login");
  signupBtn.classList.toggle("is-active", mode === "signup");
  submitLabel.innerText = mode === "login" ? "Sign In" : "Create Account";
  subtitle.innerText = mode === "login"
    ? "Sign in with your username and PIN."
    : "Create your account with a username and PIN.";
}

function clearChatView() {
  msgContainer.innerHTML = "";
  activeUsers = [];
  activeAdminUsers = [];
  const userList = document.getElementById("user-list") as HTMLDivElement;
  userList.innerHTML = "";
  (document.getElementById("user-count") as HTMLElement).innerText = "0";
  if (roomOnlineCountNode) roomOnlineCountNode.innerText = "0";
  const adminList = document.getElementById(
    "admin-user-list",
  ) as HTMLDivElement;
  if (adminList) adminList.innerHTML = "";
  const adminCount = document.getElementById("admin-user-count") as HTMLElement;
  if (adminCount) adminCount.innerText = "0";
}

async function deriveKey(password: string, salt: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"],
  );
  return await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

async function encryptMessage(text: string): Promise<string> {
  if (!encryptionKey) return text;
  try {
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      encryptionKey,
      encoder.encode(text),
    );

    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv);
    combined.set(new Uint8Array(encrypted), iv.length);
    return btoa(String.fromCharCode(...Array.from(combined)));
  } catch (error) {
    console.error("Encryption failed:", error);
    return text;
  }
}

async function decryptMessage(data: string): Promise<string> {
  if (!encryptionKey) return data;
  try {
    const combined = new Uint8Array(
      atob(data).split("").map((char) => char.charCodeAt(0)),
    );
    const iv = combined.slice(0, 12);
    const encrypted = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      encryptionKey,
      encrypted,
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    return data;
  }
}

async function requestDesktopNotificationPermission() {
  if (!notificationPrefs.desktopEnabled || !("Notification" in window)) return;
  if (Notification.permission === "default") {
    await Notification.requestPermission();
  }
}

async function submitAuth() {
  try {
    const usernameInput = document.getElementById(
      "username-input",
    ) as HTMLInputElement;
    const pinInput = document.getElementById("pin-input") as HTMLInputElement;
    const avatarInput = document.getElementById(
      "avatar-input",
    ) as HTMLInputElement;
    const roomKeyInput = document.getElementById(
      "room-key-input",
    ) as HTMLInputElement;

    const username = usernameInput.value.trim();
    const pin = pinInput.value.trim();
    const avatar = avatarInput.value.trim();
    const roomKey = roomKeyInput.value.trim();

    if (!username || !pin || !roomKey) {
      alert("Username, PIN, and room key are required.");
      return;
    }

    const authData = await requestApi<AuthSuccess>(`/api/auth/${authMode}`, {
      method: "POST",
      body: JSON.stringify({ username, pin, avatar }),
    });

    authToken = authData.token;
    currentUser = {
      id: authData.user.id,
      username: authData.user.username,
      avatar: authData.user.avatar,
      roomId: DEFAULT_ROOM,
      isAdmin: authData.user.isAdmin,
    };
    currentRoom = DEFAULT_ROOM;

    saveStoredProfile({
      username: currentUser.username,
      avatar: currentUser.avatar,
    });
    updateProfileCard();
    setAdminPanelVisibility();
    (document.getElementById("current-room-name") as HTMLElement).innerText =
      currentRoom;

    if (!window.isSecureContext || !crypto.subtle) {
      showToast(
        "Security",
        "Secure crypto is unavailable. Messages will be sent without encryption.",
      );
      encryptionKey = null;
    } else {
      encryptionKey = await deriveKey(roomKey, "chat-salt");
    }

    await requestDesktopNotificationPermission();
    document.getElementById("login-overlay")?.classList.add("hidden");
    closeSidebar();

    clearChatView();
    shouldReconnect = true;
    initSocket();

    if (currentUser.isAdmin) {
      await loadAdminUsers();
    }

    showToast(
      "Account",
      authMode === "login"
        ? "Signed in successfully."
        : "Account created successfully.",
    );
    pinInput.value = "";
  } catch (error) {
    alert(error instanceof Error ? error.message : String(error));
  }
}

function initSocket() {
  if (!authToken) return;
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  socket = new WebSocket(`${protocol}//${window.location.host}`);

  socket.onopen = () => {
    if (!authToken) return;
    socket?.send(JSON.stringify({
      type: "join",
      payload: {
        token: authToken,
        roomId: currentRoom,
      },
    }));
  };

  socket.onmessage = async (event: MessageEvent) => {
    const data: SocketMessage = JSON.parse(event.data);

    switch (data.type) {
      case "history":
        msgContainer.innerHTML = "";
        if (data.messages) {
          for (const msg of data.messages) {
            await renderMessage(msg);
          }
        }
        scrollToBottom();
        break;
      case "message":
        if (data.message) {
          const decrypted = await decryptMessage(data.message.content);
          await renderMessage(data.message, decrypted);
          await notifyUser(data.message, decrypted);
        }
        scrollToBottom();
        break;
      case "room_list":
        if (data.rooms) renderRoomList(data.rooms);
        break;
      case "user_list":
        if (data.users) renderUserList(data.users);
        break;
      case "session_info":
        if (data.payload) {
          currentUser.id = data.payload.userId || currentUser.id;
          currentUser.avatar = data.payload.avatar || currentUser.avatar;
          currentUser.username = data.payload.username || currentUser.username;
          currentUser.isAdmin = Boolean(data.payload.isAdmin);
          updateProfileCard();
          setAdminPanelVisibility();
          if (currentUser.isAdmin) {
            await loadAdminUsers();
          }
        }
        break;
      case "error":
        showToast(
          "Server",
          data.error || data.payload?.message || "Server error",
        );
        if ((data.error || "").toLowerCase().includes("auth")) {
          shouldReconnect = false;
        }
        break;
      case "account_deleted":
        await forceLogout(data.payload?.message || "Your account was removed.");
        break;
      case "delete_message":
        if (data.payload?.messageId) {
          const el = document.getElementById(`msg-${data.payload.messageId}`);
          if (el) {
            el.style.opacity = "0";
            el.style.transform = "scale(0.9)";
            setTimeout(() => el.remove(), 300);
          }
        }
        break;
      case "clear_user_messages":
        if (data.payload?.userId) {
          const messages = msgContainer.querySelectorAll(".chat-row");
          messages.forEach((el) => {
            // We need a way to know who sent the message from the DOM
            // or just refresh the history. Refreshing history is safer.
          });
          refreshCurrentRoomHistory();
        }
        break;
      case "info":
        if (data.payload?.message) {
          showToast("Info", data.payload.message);
        }
        break;
    }
  };

  socket.onclose = () => {
    if (shouldReconnect && authToken) {
      setTimeout(() => initSocket(), 3000);
    }
  };
}

async function sendMessage() {
  const content = msgInput.value.trim();
  if (!content) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    showToast("Connection", "Not connected to the server yet.");
    return;
  }
  if (content === "/clear") {
    socket.send(JSON.stringify({
      type: "message",
      payload: { content: "/clear" },
    }));
    msgInput.value = "";
    return;
  }

  const encrypted = await encryptMessage(content);
  socket.send(JSON.stringify({
    type: "message",
    payload: {
      content: encrypted,
      replyToId,
      isSpoiler: isSpoilerNext,
      ttl: currentTTL || undefined,
    },
  }));

  msgInput.value = "";
  cancelReply();
  if (isSpoilerNext) toggleSpoiler();
}

function toggleSpoiler() {
  isSpoilerNext = !isSpoilerNext;
  const btn = document.getElementById("spoiler-toggle") as HTMLButtonElement;
  btn.classList.toggle("is-active", isSpoilerNext);
}

function cycleTTL() {
  const btn = document.getElementById("ttl-toggle") as HTMLButtonElement;
  const label = document.getElementById("ttl-label") as HTMLElement;
  
  if (currentTTL === null) {
    currentTTL = 10000;
    label.innerText = "10S";
    btn.classList.add("ttl-active");
  } else if (currentTTL === 10000) {
    currentTTL = 30000;
    label.innerText = "30S";
    btn.classList.add("ttl-active");
  } else {
    currentTTL = null;
    label.innerText = "OFF";
    btn.classList.remove("ttl-active");
  }
}

function replyTo(
  id: string,
  encodedUsername: string,
  encodedContentExcerpt: string,
) {
  replyToId = id;
  const username = decodeInline(encodedUsername);
  const contentExcerpt = decodeInline(encodedContentExcerpt);
  document.getElementById("reply-preview")?.classList.remove("hidden");
  (document.getElementById("reply-username") as HTMLElement).innerText =
    username;
  (document.getElementById("reply-content-preview") as HTMLElement).innerText =
    contentExcerpt;
  msgInput.focus();
}

function cancelReply() {
  replyToId = null;
  document.getElementById("reply-preview")?.classList.add("hidden");
}

async function uploadFile(file: File): Promise<string | null> {
  const formData = new FormData();
  formData.append("file", file);

  try {
    const result = await requestApi<{ url: string }>("/api/upload", {
      method: "POST",
      body: formData,
      headers: {
        // Fetch usually sets the correct multipart/form-data boundary automatically
        // if we don't manually set Content-Type.
      },
    }, true);
    return result.url;
  } catch (err: any) {
    showToast("Upload Error", err.message);
    return null;
  }
}

function appendUploadedUrlsToComposer(urls: string[]) {
  if (urls.length === 0) return;
  const existing = msgInput.value.trimEnd();
  const combined = existing
    ? `${existing}\n${urls.join("\n")}`
    : urls.join("\n");
  msgInput.value = combined;
  msgInput.focus();
}

async function uploadMediaFiles(files: File[]) {
  if (files.length === 0) return;
  const uploadedUrls: string[] = [];

  for (const file of files) {
    showToast("Attachment", `Uploading ${file.name}...`);
    const url = await uploadFile(file);
    if (url) {
      uploadedUrls.push(url);
    }
  }

  if (uploadedUrls.length > 0) {
    appendUploadedUrlsToComposer(uploadedUrls);
    const plural = uploadedUrls.length === 1 ? "" : "s";
    showToast(
      "Attachment",
      `${uploadedUrls.length} file${plural} uploaded and link${plural} added!`,
    );
  }
}

async function handleFileUpload(event: Event) {
  const target = event.target as HTMLInputElement;
  const files = target.files ? Array.from(target.files) : [];
  if (files.length === 0) return;

  await uploadMediaFiles(files);
  target.value = "";
}

// Global drag and drop support
window.addEventListener("dragover", (e) => {
  e.preventDefault();
  e.stopPropagation();
});

window.addEventListener("drop", async (e) => {
  e.preventDefault();
  e.stopPropagation();

  if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
    const files = Array.from(e.dataTransfer.files);
    await uploadMediaFiles(files);
  }
});

function revealSpoiler(el: HTMLElement) {
  if (el.classList.contains("revealed")) return;
  el.classList.add("revealed");

  // Auto re-blur after 25 seconds
  setTimeout(() => {
    el.classList.remove("revealed");
  }, 25000);
}

function replyToLastMessage() {
  const messages = msgContainer.querySelectorAll(".chat-row");
  if (messages.length === 0) return;
  const lastMsg = messages[messages.length - 1];
  const id = lastMsg.id.replace("msg-", "");
  const usernameElement = lastMsg.querySelector(".sender-name") ||
    lastMsg.querySelector("span[class*='text-[var(--accent-color)]']");
  const contentElement = lastMsg.querySelector(".message-content") ||
    lastMsg.querySelector("div[class*='text-[15px]']");

  if (id && usernameElement && contentElement) {
    replyTo(
      id,
      encodeInline(usernameElement.textContent || ""),
      encodeInline(contentElement.textContent || ""),
    );
  }
}

function escapeWithLineBreaks(value: string): string {
  return escapeHtml(value).replace(/\n/g, "<br>");
}

function getUrlExtension(url: string): string {
  try {
    const parsed = new URL(url, window.location.origin);
    const lowerPath = parsed.pathname.toLowerCase();
    const dotIndex = lowerPath.lastIndexOf(".");
    if (dotIndex === -1) return "";
    return lowerPath.slice(dotIndex + 1);
  } catch {
    return "";
  }
}

function createDownloadButton(url: string): string {
  const safeUrl = escapeHtml(url);
  return `<a href="${safeUrl}" download class="inline-flex items-center gap-1 text-[10px] bg-[var(--surface-soft)] px-2 py-1 rounded hover:bg-[var(--accent-soft)] transition-colors ml-2 no-underline text-[var(--accent-color)] h-fit"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg> DOWNLOAD</a>`;
}

function renderMediaMarkup(rawUrl: string): string {
  const fullUrl = rawUrl.startsWith("/static/")
    ? `${window.location.origin}${rawUrl}`
    : rawUrl;
  const extension = getUrlExtension(fullUrl);
  const safeFullUrl = escapeHtml(fullUrl);
  const safeRawUrl = escapeHtml(rawUrl);
  const downloadButton = createDownloadButton(fullUrl);

  if (IMAGE_EXTENSIONS.has(extension)) {
    return `<div class="mt-2 flex flex-col gap-2 max-w-full"><img src="${safeFullUrl}" class="max-w-md w-full rounded-md border border-[var(--border-color)]" loading="lazy"> ${downloadButton}</div>`;
  }

  if (AUDIO_EXTENSIONS.has(extension)) {
    return `<div class="mt-2 flex items-center gap-2 flex-wrap"><audio controls src="${safeFullUrl}" class="h-8 max-w-[240px]"></audio> ${downloadButton}</div>`;
  }

  return `<a href="${safeFullUrl}" target="_blank" rel="noopener noreferrer" class="text-[var(--accent-color)] underline">${safeRawUrl}</a> ${downloadButton}`;
}

function formatMessageContent(content: string): string {
  let html = "";
  let cursor = 0;

  for (const match of content.matchAll(MEDIA_URL_REGEX)) {
    const index = match.index ?? 0;
    const url = match[0];
    html += processMentions(content.slice(cursor, index));
    html += renderMediaMarkup(url);
    cursor = index + url.length;
  }

  html += processMentions(content.slice(cursor));
  return html;
}

function processMentions(text: string): string {
  const safeText = escapeWithLineBreaks(text);
  return safeText.replace(MENTION_REGEX, (match) => {
    const username = match.substring(1);
    return `<span class="mention-tag" onclick="insertMentionField('${
      escapeHtml(username)
    }')">@${escapeHtml(username)}</span>`;
  });
}

function updateMentionSuggestions() {
  const suggestionsEl = document.getElementById(
    "mention-suggestions",
  ) as HTMLDivElement;
  if (mentionQuery === null) {
    suggestionsEl.style.display = "none";
    return;
  }

  const filtered = activeUsers.filter((u) =>
    u.username.toLowerCase().includes(mentionQuery!.toLowerCase())
  );

  if (filtered.length === 0) {
    suggestionsEl.style.display = "none";
    return;
  }

  if (selectedSuggestionIndex >= filtered.length) selectedSuggestionIndex = 0;

  suggestionsEl.innerHTML = filtered.map((u, i) => `
        <div class="suggestion-item ${
    i === selectedSuggestionIndex ? "active" : ""
  }" onclick="insertMention('${encodeInline(u.username)}')">
            <img src="${escapeHtml(u.avatar)}" alt="">
            <span>${escapeHtml(u.username)}</span>
        </div>
    `).join("");
  suggestionsEl.style.display = "block";
}

function insertMention(encodedUsername: string) {
  const username = decodeInline(encodedUsername);
  const pos = msgInput.selectionStart;
  const text = msgInput.value;
  const atIndex = text.lastIndexOf("@", pos - 1);
  if (atIndex === -1) return;

  const before = text.substring(0, atIndex);
  const after = text.substring(pos);
  msgInput.value = before + "@" + username + " " + after;
  mentionQuery = null;
  updateMentionSuggestions();
  msgInput.focus();
}

function insertMentionField(username: string) {
  msgInput.value += ` @${username} `;
  msgInput.focus();
}

(window as any).insertMention = insertMention;
(window as any).insertMentionField = insertMentionField;
(window as any).cycleTTL = cycleTTL;

async function renderMessage(msg: MessageData, resolvedContent?: string) {
  const decryptedContent = resolvedContent ?? await decryptMessage(msg.content);
  const isMe = msg.userId === currentUser.id;
  const muted = !isMe && isMessageMuted(msg);
  const timestamp = new Date(msg.timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
  const encodedUsername = encodeInline(msg.username);
  const encodedAvatar = encodeInline(msg.avatar);
  const encodedUserId = encodeInline(msg.userId || "");
  const replySnippet = encodeInline(decryptedContent.substring(0, 60));

  const isMentioned = !isMe &&
    decryptedContent.toLowerCase().includes(
      `@${currentUser.username.toLowerCase()}`,
    );
  const div = document.createElement("div");
  div.className = `chat-row flex flex-col ${
    isMe ? "items-end" : "items-start"
  } group w-full mb-6 ${isMentioned ? "mention-highlight" : ""}`;
  div.id = `msg-${msg.id}`;

  let replyHtml = "";
  if (msg.replyToId) {
    const repliedEl = document.getElementById(`msg-${msg.replyToId}`);
    let preview = "";
    if (repliedEl) {
      const rName =
        repliedEl.querySelector("span[class*='text-[var(--accent-color)]']")
          ?.textContent || "User";
      const rContent =
        repliedEl.querySelector(".message-content")?.textContent ||
        repliedEl.querySelector(".spoiler-content")?.textContent || "Media";
      const safeRName = escapeHtml(rName);
      const safeRContent = escapeHtml(rContent.substring(0, 30));
      preview =
        `<div class="text-[10px] opacity-40 italic mb-1 truncate max-w-[200px]">@${safeRName}: ${safeRContent}...</div>`;
    }

    const encodedReplyToId = encodeURIComponent(msg.replyToId);
    replyHtml = `
            <button onclick="scrollToMessage('${encodedReplyToId}')" class="reply-anchor flex flex-col items-start">
                ${preview}
                <span class="opacity-60">replying to #${
      escapeHtml(msg.replyToId.substring(0, 8))
    }</span>
            </button>
        `;
  }

  let contentHtml = "";
  if (muted) {
    contentHtml = `
            <div class="muted-message">
                muted ${escapeHtml(msg.username)} message
                <button onclick="toggleUserMute('${encodedUserId}','${encodedUsername}','${encodedAvatar}')" class="inline-unmute-btn">unmute</button>
            </div>
        `;
  } else {
    const processedContent = formatMessageContent(decryptedContent);

    if (msg.isSpoiler) {
      contentHtml =
        `<div class="spoiler-content" onclick="revealSpoiler(this)">${processedContent}</div>`;
    } else {
      contentHtml = `<div class="message-content">${processedContent}</div>`;
    }
  }

  const actionButtons = (!isMe && !muted)
    ? `
        <div class="message-actions opacity-0 group-hover:opacity-100 transition-opacity">
            <button onclick="replyTo('${msg.id}','${encodedUsername}','${replySnippet}')" class="text-[10px] text-[var(--accent-color)] hover:underline uppercase mr-3">reply</button>
            <button onclick="toggleUserMute('${encodedUserId}','${encodedUsername}','${encodedAvatar}')" class="text-[10px] text-[var(--text-muted)] hover:text-[var(--danger)] uppercase">mute</button>
        </div>
    `
    : "";

  div.innerHTML = `
        ${replyHtml}
        <div class="flex items-start gap-4 ${
    isMe ? "flex-row-reverse" : "flex-row"
  }">
            <img src="${escapeHtml(msg.avatar)}" alt="${
    escapeHtml(msg.username)
  }" class="w-8 h-8 rounded-sm opacity-40 grayscale hover:grayscale-0 transition-all">
            <div class="flex-1 min-w-0">
                <div class="flex items-center gap-3 mb-1 ${
    isMe ? "justify-end" : "justify-start"
  }">
                    <span class="text-[11px] font-bold text-[var(--accent-color)] uppercase tracking-widest">${
    escapeHtml(msg.username)
  }</span>
                    <span class="text-[9px] text-[var(--text-muted)] font-mono opacity-40">${timestamp}</span>
                    ${
    msg.ttl
      ? `<span class="ttl-tag"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> ${
        msg.ttl / 1000
      }s</span>`
      : ""
  }
                </div>
                <div class="${
    isMe ? "text-right" : "text-left"
  } text-[17px] leading-relaxed text-[var(--text-color)]">
                    <div class="inline-block w-full">${contentHtml}</div>
                    ${actionButtons}
                </div>
            </div>
        </div>
    `;

  msgContainer.appendChild(div);
}

function scrollToMessage(id: string) {
  const element = document.getElementById(`msg-${id}`);
  if (!element) return;
  element.scrollIntoView({ behavior: "smooth", block: "center" });
  element.classList.add("highlight-message");
  setTimeout(() => element.classList.remove("highlight-message"), 1800);
}

function renderRoomList(roomNames: string[]) {
  const container = document.getElementById("room-list") as HTMLDivElement;
  container.innerHTML = roomNames.map((name) => {
    const active = name === currentRoom;
    return `
            <button onclick="switchRoom('${
      encodeInline(name)
    }')" class="flex items-center justify-between w-full py-1.5 px-2 rounded hover:bg-[rgba(255,255,255,0.05)] transition-colors ${
      active ? "text-[var(--accent-color)]" : "text-[var(--text-muted)]"
    }">
                <span class="text-xs ${
      active ? "opacity-100" : "opacity-85"
    }"># ${escapeHtml(name)}</span>
                ${
      active
        ? "<div class='w-1 h-1 rounded-full bg-[var(--accent-color)]'></div>"
        : ""
    }
            </button>
        `;
  }).join("");
}

function renderUserList(userList: RoomUser[]) {
  activeUsers = userList;
  const container = document.getElementById("user-list") as HTMLDivElement;
  const onlineCount = userList.length.toString();
  (document.getElementById("user-count") as HTMLElement).innerText =
    onlineCount;
  if (roomOnlineCountNode) roomOnlineCountNode.innerText = onlineCount;

  container.innerHTML = userList.map((user) => {
    const isMe = user.id === currentUser.id;
    const muted = !isMe && isUserMuted(user.id, user.username);
    const encodedId = encodeInline(user.id);
    const encodedUsername = encodeInline(user.username);
    const encodedAvatar = encodeInline(user.avatar);

    return `
            <div class="flex items-center justify-between py-1 group">
                <div class="flex items-center gap-3 min-w-0">
                    <div class="w-2 h-2 rounded-full bg-[var(--accent-color)]"></div>
                    <span class="text-xs text-[var(--text-color)] opacity-90 truncate">${
      escapeHtml(user.username)
    }</span>
                </div>
                ${
      isMe
        ? `<span class="text-[10px] text-[var(--accent-color)] opacity-40 uppercase font-bold tracking-widest">you</span>`
        : `
                    <button onclick="toggleUserMute('${encodedId}','${encodedUsername}','${encodedAvatar}')" class="mini-action-btn opacity-0 group-hover:opacity-100 transition-all">
                        ${muted ? "unmute" : "mute"}
                    </button>
                `
    }
            </div>
        `;
  }).join("");
}

function renderAdminUsers(users: AdminUser[]) {
  activeAdminUsers = users;
  const container = document.getElementById(
    "admin-user-list",
  ) as HTMLDivElement;
  const count = document.getElementById("admin-user-count") as HTMLElement;
  count.innerText = users.length.toString();

  if (users.length === 0) {
    container.innerHTML =
      `<p class="text-[12px] text-[var(--text-muted)]">No users found</p>`;
    return;
  }

  container.innerHTML = users.map((user) => {
    const encodedId = encodeInline(user.id);
    const encodedUsername = encodeInline(user.username);
    const canDelete = !user.isAdmin && user.id !== currentUser.id;
    return `
            <div class="flex items-center justify-between py-1 group">
                <div class="min-w-0">
                    <p class="text-xs text-[var(--text-color)] truncate lowercase">${
      escapeHtml(user.username)
    }</p>
                    <p class="text-[9px] text-[var(--text-muted)] opacity-80 uppercase tracking-tighter">
                        ${user.isAdmin ? "admin" : "user"} • ${
      user.isOnline ? "online" : "offline"
    }
                    </p>
                </div>
                ${
      canDelete
        ? `<button onclick="deleteUserAccount('${encodedId}','${encodedUsername}')" class="mini-action-btn danger opacity-0 group-hover:opacity-100 transition-all">delete</button>`
        : `<span class="text-[9px] text-[var(--text-muted)] opacity-30 uppercase font-bold tracking-widest">${
          user.isAdmin ? "root" : "self"
        }</span>`
    }
            </div>
        `;
  }).join("");
}

async function loadAdminUsers() {
  if (!currentUser.isAdmin || !authToken) return;
  try {
    const data = await requestApi<{ users: AdminUser[] }>("/api/admin/users", {
      method: "GET",
    }, true);
    renderAdminUsers(data.users || []);
  } catch (error) {
    showToast("Admin", error instanceof Error ? error.message : String(error));
  }
}

async function deleteUserAccount(
  encodedUserId: string,
  encodedUsername: string,
) {
  if (!currentUser.isAdmin || !authToken) return;
  const userId = decodeInline(encodedUserId);
  const username = decodeInline(encodedUsername);
  if (!confirm(`Delete user "${username}" and remove their messages?`)) return;

  try {
    await requestApi("/api/admin/delete-user", {
      method: "POST",
      body: JSON.stringify({ userId }),
    }, true);

    showToast("Admin", `Deleted ${username}.`);
    await loadAdminUsers();
    refreshCurrentRoomHistory();
  } catch (error) {
    alert(error instanceof Error ? error.message : String(error));
  }
}

async function wipeServerData() {
  if (!currentUser.isAdmin || !authToken) return;
  if (
    !confirm(
      "This removes all non-admin users and clears all messages. Continue?",
    )
  ) return;

  try {
    await requestApi("/api/admin/wipe", {
      method: "POST",
      body: JSON.stringify({}),
    }, true);

    showToast("Admin", "Server user/message data wiped.");
    clearChatView();
    await loadAdminUsers();
  } catch (error) {
    alert(error instanceof Error ? error.message : String(error));
  }
}

function createRoom() {
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    showToast("Connection", "Connect first before creating rooms.");
    return;
  }
  const name = prompt("Room name:");
  if (!name?.trim()) return;
  socket.send(JSON.stringify({
    type: "create_room",
    payload: { roomName: name.trim() },
  }));
  closeSidebar();
}

function switchRoom(encodedName: string) {
  const name = decodeInline(encodedName);
  if (!name || name === currentRoom) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  currentRoom = name;
  (document.getElementById("current-room-name") as HTMLElement).innerText =
    name;
  socket.send(JSON.stringify({
    type: "switch_room",
    payload: { roomId: name },
  }));
  closeSidebar();
}

function refreshCurrentRoomHistory() {
  if (!socket || socket.readyState !== WebSocket.OPEN) return;
  socket.send(JSON.stringify({
    type: "switch_room",
    payload: { roomId: currentRoom },
  }));
}

function scrollToBottom() {
  msgContainer.scrollTop = msgContainer.scrollHeight;
}

function showToast(title: string, message: string) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = "toast";
  toast.innerHTML = `
        <div class="toast-accent"></div>
        <div class="toast-text">
            <div class="toast-title">${escapeHtml(title)}</div>
            <div class="toast-message">${escapeHtml(message)}</div>
        </div>
    `;

  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add("fade-out");
    setTimeout(() => toast.remove(), 250);
  }, 3500);
}

async function playMessageSound() {
  if (!notificationPrefs.soundEnabled) return;
  try {
    messageSound.currentTime = 0;
    await messageSound.play();
  } catch {
    // Browser may block autoplay before user interaction.
  }
}

async function notifyUser(msg: MessageData, decryptedContent: string) {
  if (msg.userId === currentUser.id) return;
  if (isMessageMuted(msg)) return;

  if (!isFocused) {
    unreadCount++;
    updateTitle();
  }

  if (notificationPrefs.toastEnabled) {
    showToast(msg.username, decryptedContent);
  }

  await playMessageSound();

  if (
    notificationPrefs.desktopEnabled &&
    !isFocused &&
    "Notification" in window &&
    Notification.permission === "granted"
  ) {
    new Notification(`New message from ${msg.username}`, {
      body: decryptedContent,
      icon: msg.avatar,
    });
  }
}

function toggleUserMute(
  encodedUserId: string,
  encodedUsername: string,
  encodedAvatar: string,
) {
  const userId = decodeInline(encodedUserId) || undefined;
  const username = decodeInline(encodedUsername);
  const avatar = decodeInline(encodedAvatar) ||
    `https://api.dicebear.com/7.x/avataaars/svg?seed=${
      encodeURIComponent(username)
    }`;
  if (!username || userId === currentUser.id) return;

  if (isUserMuted(userId, username)) {
    unmuteUser(userId, username);
    showToast("Mute list", `${username} has been unmuted.`);
  } else {
    muteUser(userId, username, avatar);
    showToast("Mute list", `${username} has been muted.`);
  }

  renderUserList(activeUsers);
  refreshCurrentRoomHistory();
}

async function setDesktopEnabled(enabled: boolean) {
  notificationPrefs.desktopEnabled = enabled;
  saveNotificationPreferences();
  if (enabled) {
    await requestDesktopNotificationPermission();
  }
}

function setSoundEnabled(enabled: boolean) {
  notificationPrefs.soundEnabled = enabled;
  saveNotificationPreferences();
}

function setToastEnabled(enabled: boolean) {
  notificationPrefs.toastEnabled = enabled;
  saveNotificationPreferences();
}

async function forceLogout(reason?: string) {
  shouldReconnect = false;
  unreadCount = 0;
  updateTitle();
  encryptionKey = null;
  replyToId = null;
  isSpoilerNext = false;

  const tokenForLogout = authToken;
  authToken = null;

  if (tokenForLogout) {
    try {
      await requestApi("/api/auth/logout", {
        method: "POST",
        body: JSON.stringify({}),
        headers: {
          Authorization: `Bearer ${tokenForLogout}`,
        },
      });
    } catch {
      // Ignore logout API failures
    }
  }

  if (socket) {
    try {
      socket.close();
    } catch {
      // Ignore socket close errors.
    }
    socket = null;
  }

  currentUser = {
    id: "",
    username: "",
    avatar: "",
    roomId: DEFAULT_ROOM,
    isAdmin: false,
  };
  currentRoom = DEFAULT_ROOM;
  (document.getElementById("current-room-name") as HTMLElement).innerText =
    DEFAULT_ROOM;
  setAdminPanelVisibility();
  closeSidebar();
  clearChatView();
  updateProfileCard();
  document.getElementById("login-overlay")?.classList.remove("hidden");

  if (reason) {
    alert(reason);
  }
}

async function logout() {
  if (!confirm("Leave this chat session?")) return;
  await forceLogout();
}

function changeTheme(themeFile: string) {
  const themeLink = document.getElementById("theme-link") as HTMLLinkElement;
  themeLink.href = themeFile ? `/themes/${themeFile}` : "";
  localStorage.setItem(THEME_STORAGE_KEY, themeFile);
}

function initializeSettings() {
  restoreProfileInputs();
  loadNotificationPreferences();
  loadMutedUsers();
  renderMutedUsers();
  syncNotificationControls();
  updateTitle();
  setAuthMode("login");
  updateProfileCard();
  setAdminPanelVisibility();

  let savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  if (savedTheme === null) savedTheme = "gruvbox.css";

  changeTheme(savedTheme);
}

window.addEventListener("keydown", (event: KeyboardEvent) => {
  const isInput = (event.target as HTMLElement).tagName === "INPUT" ||
    (event.target as HTMLElement).tagName === "TEXTAREA";

  if (event.key === "Escape") {
    if (isSidebarOpen()) {
      closeSidebar();
      return;
    }
    if (replyToId) {
      cancelReply();
    }
  }

  // Single key shortcuts when not in an input
  if (!isInput) {
    const key = event.key.toLowerCase();
    
    if (key === "s") {
      event.preventDefault();
      toggleSpoiler();
      return;
    }
    
    if (key === "t") {
      event.preventDefault();
      (window as any).cycleTTL();
      return;
    }
    
    if (key === "e") {
      event.preventDefault();
      document.getElementById("file-upload")?.click();
      return;
    }
    
    if (key === "n") {
      event.preventDefault();
      createRoom();
      return;
    }

    if (key === "r") {
      event.preventDefault();
      replyToLastMessage();
      return;
    }
  }
});

window.addEventListener("focus", () => {
  isFocused = true;
  unreadCount = 0;
  updateTitle();
});

window.addEventListener("blur", () => {
  isFocused = false;
});

window.addEventListener("resize", () => {
  if (!isMobileLayout() && isSidebarOpen()) {
    closeSidebar();
    return;
  }
  syncSidebarState();
});

// Register global functions early to avoid issues if initialization crashes
(window as any).submitAuth = submitAuth;
(window as any).setAuthMode = setAuthMode;
(window as any).toggleSpoiler = toggleSpoiler;
(window as any).replyTo = replyTo;
(window as any).cancelReply = cancelReply;
(window as any).scrollToMessage = scrollToMessage;
(window as any).createRoom = createRoom;
(window as any).switchRoom = switchRoom;
(window as any).sendMessage = sendMessage;
(window as any).changeTheme = changeTheme;
(window as any).logout = logout;
(window as any).setSoundEnabled = setSoundEnabled;
(window as any).setDesktopEnabled = setDesktopEnabled;
(window as any).setToastEnabled = setToastEnabled;
(window as any).toggleUserMute = toggleUserMute;
(window as any).toggleSidebar = toggleSidebar;
(window as any).closeSidebar = closeSidebar;
(window as any).loadAdminUsers = loadAdminUsers;
(window as any).deleteUserAccount = deleteUserAccount;
(window as any).wipeServerData = wipeServerData;
(window as any).handleFileUpload = handleFileUpload;
(window as any).revealSpoiler = revealSpoiler;
(window as any).replyToLastMessage = replyToLastMessage;
(window as any).openProfileModal = openProfileModal;
(window as any).closeProfileModal = closeProfileModal;
(window as any).saveProfile = saveProfile;

msgInput?.addEventListener("input", (e) => {
  const pos = msgInput.selectionStart;
  const text = msgInput.value;
  const lastSpace = text.lastIndexOf(" ", pos - 1);
  const lastAt = text.lastIndexOf("@", pos - 1);

  if (lastAt !== -1 && lastAt > lastSpace) {
    mentionQuery = text.substring(lastAt + 1, pos);
    selectedSuggestionIndex = 0;
  } else {
    mentionQuery = null;
  }
  updateMentionSuggestions();
});

msgInput?.addEventListener("keydown", (e) => {
  if (mentionQuery !== null) {
    const suggestionsEl = document.getElementById("mention-suggestions");
    const items = suggestionsEl?.querySelectorAll(".suggestion-item");

    if (e.key === "ArrowDown") {
      e.preventDefault();
      selectedSuggestionIndex = (selectedSuggestionIndex + 1) %
        (items?.length || 1);
      updateMentionSuggestions();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      selectedSuggestionIndex =
        (selectedSuggestionIndex - 1 + (items?.length || 1)) %
        (items?.length || 1);
      updateMentionSuggestions();
    } else if (e.key === "Enter" || e.key === "Tab") {
      const activeItem = suggestionsEl?.querySelector(
        ".suggestion-item.active",
      ) as HTMLElement;
      if (activeItem) {
        e.preventDefault();
        activeItem.click();
      }
    } else if (e.key === "Escape") {
      mentionQuery = null;
      updateMentionSuggestions();
    }
  }
});

msgInput?.addEventListener("keypress", (event: KeyboardEvent) => {
  if (event.key === "Enter" && !event.shiftKey && mentionQuery === null) {
    event.preventDefault();
    sendMessage();
  }
});

initializeSettings();
syncSidebarState();
