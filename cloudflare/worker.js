import { connect } from "cloudflare:sockets";
import {
  concatBytes,
  isPrivateTarget,
  normalizeBinaryData,
  parseSrvData,
  parseTarget,
  selectSrvRecord,
  validateMinecraftHandshake
} from "../src/protocol.js";

const encoder = new TextEncoder();
const MAX_HANDSHAKE_BYTES = 65536;

function decodeBase64url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(base64);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function verifyPayload(secret, token) {
  if (!secret || secret.length < 16 || !token) throw new Error("missing relay authentication");
  const pieces = token.split(".");
  if (pieces.length !== 2) throw new Error("malformed relay token");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("HMAC", key, decodeBase64url(pieces[1]), encoder.encode(pieces[0]));
  if (!valid) throw new Error("invalid relay token");
  let payload;
  try {
    payload = JSON.parse(new TextDecoder().decode(decodeBase64url(pieces[0])));
  } catch {
    throw new Error("malformed relay token payload");
  }
  if (payload.v !== 1 || !Number.isInteger(payload.exp) ||
      payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("expired relay token");
  }
  return payload;
}

async function verifyToken(secret, token, target) {
  const payload = await verifyPayload(secret, token);
  if (payload.target !== target) throw new Error("wrong-target relay token");
}

async function verifyScopedToken(secret, token, scope) {
  const payload = await verifyPayload(secret, token);
  if (payload.scope !== scope) throw new Error("wrong-scope relay token");
}

function errorResponse(status, message) {
  return new Response(`${message}\n`, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" }
  });
}

async function resolveMinecraftDestination(target, env) {
  if (target.explicitPort) return { host: target.host, port: target.port, viaSrv: false };
  try {
    const endpoint = new URL(String(env.RELAY_DNS_HTTPS ?? "https://cloudflare-dns.com/dns-query"));
    endpoint.searchParams.set("name", `_minecraft._tcp.${target.host}`);
    endpoint.searchParams.set("type", "SRV");
    const response = await fetch(endpoint, { headers: { accept: "application/dns-json" } });
    if (response.ok) {
      const body = await response.json();
      const record = selectSrvRecord((Array.isArray(body.Answer) ? body.Answer : [])
        .filter((answer) => Number(answer.type) === 33)
        .map((answer) => parseSrvData(answer.data))
        .filter(Boolean));
      if (record) return { host: record.name, port: record.port, viaSrv: true };
    }
  } catch {}
  return { host: target.host, port: target.port, viaSrv: false };
}

function webSocketCloseReason(value) {
  let reason = String(value || "relay closed").slice(0, 120);
  while (encoder.encode(reason).byteLength > 123) reason = reason.slice(0, -1);
  return reason || "relay closed";
}

function webSocketCloseCode(value, fallback = 1011) {
  const code = Number(value);
  return code === 1000 || code === 1001 || code === 1002 || code === 1003 ||
      (code >= 1007 && code <= 1014) || (code >= 3000 && code <= 4999) ? code : fallback;
}

const LAN_CODE_RE = /^[A-Z0-9]{6}$/;
const LAN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

function randomLANCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let code = "";
  for (const byte of bytes) code += LAN_ALPHABET[byte % LAN_ALPHABET.length];
  return code;
}

function randomPeerId() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let id = "";
  for (const byte of bytes) id += LAN_ALPHABET[byte % LAN_ALPHABET.length];
  return id;
}

function ascii(value) {
  return Uint8Array.from(value ?? "", (char) => char.charCodeAt(0) & 255);
}

function packet(parts) {
  const size = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function ascii8(value) {
  const bytes = ascii(value);
  if (bytes.byteLength > 255) throw new Error("relay field is too long");
  return packet([Uint8Array.of(bytes.byteLength), bytes]);
}

function ascii16(value) {
  const bytes = ascii(value);
  if (bytes.byteLength > 65535) throw new Error("relay field is too long");
  return packet([Uint8Array.of(bytes.byteLength >>> 8, bytes.byteLength & 255), bytes]);
}

function handshakePacket(type, code) {
  return packet([Uint8Array.of(0x00, type, 1), ascii8(code)]);
}

function iceServersPacket(env) {
  const configured = String(env.RELAY_ICE_SERVERS ?? "stun:stun.cloudflare.com:3478")
    .split(",").map((entry) => entry.trim()).filter(Boolean).slice(0, 16);
  const entries = configured.map((entry) => {
    const fields = entry.split(";");
    const address = fields[0];
    const username = fields.length > 1 ? fields[1] : "";
    const password = fields.length > 2 ? fields.slice(2).join(";") : "";
    return packet([Uint8Array.of(username ? 0x54 : 0x53), ascii16(address), ascii8(username), ascii8(password)]);
  });
  return packet([Uint8Array.of(0x01, entries.length >>> 8, entries.length & 255), ...entries]);
}

function pongPacket() {
  return packet([Uint8Array.of(0x69, 1), ascii8("Eaglercraft 26.2 dual-purpose relay"), ascii8("Eaglercraft 26.2 Cloudflare")]);
}

function errorPacket(code, reason) {
  return packet([Uint8Array.of(0xff, code & 255), ascii16(reason)]);
}

function disconnectPacket(peer, code, reason) {
  return packet([Uint8Array.of(0xfe), ascii8(peer), Uint8Array.of(code & 255), ascii16(reason)]);
}

function openMinecraftUpstream(request, env) {
  const configured = String(env.RELAY_MINECRAFT_UPSTREAM ?? "").trim();
  const upstream = new URL(configured);
  if (upstream.protocol !== "https:") throw new Error("Minecraft upstream must use HTTPS/WSS");
  upstream.pathname = `${upstream.pathname.replace(/\/$/, "")}/minecraft`;
  upstream.search = new URL(request.url).search;
  return fetch(new Request(upstream, request));
}


const PARTY_NAME_RE = /^[A-Za-z0-9_]{1,16}$/;
const PARTY_CODE_RE = /^[A-Z0-9]{6}$/;
const PARTY_STALE_MS = 30000;
const PARTY_MAX_MEMBERS = 8;

function partyResponse(request, data, status = 200) {
  const origin = request.headers.get("origin") || "*";
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "POST, OPTIONS",
      "access-control-allow-headers": "content-type, authorization",
      "vary": "Origin"
    }
  });
}

async function partyBody(request) {
  const raw = await request.text();
  if (raw.length > 8192) throw new Error("party request is too large");
  try { return JSON.parse(raw || "{}"); }
  catch { throw new Error("invalid JSON request"); }
}

function partyToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function partyTokenHash(token) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(String(token)));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function partyName(value) {
  const name = String(value ?? "").trim();
  if (!PARTY_NAME_RE.test(name)) throw new Error("player name must be 1-16 letters, numbers or underscores");
  return name;
}

function partyCode(value) {
  const code = String(value ?? "").trim().toUpperCase();
  if (!PARTY_CODE_RE.test(code)) throw new Error("party code must contain six letters or numbers");
  return code;
}

async function partyDelete(db, code) {
  await db.prepare("DELETE FROM vbv_party_members WHERE party_code = ?").bind(code).run();
  await db.prepare("DELETE FROM vbv_parties WHERE code = ?").bind(code).run();
}

async function partyCleanup(db, code, now) {
  const party = await db.prepare(
    "SELECT code, host_member_id, expires_at FROM vbv_parties WHERE code = ?"
  ).bind(code).first();
  if (!party) return null;
  const host = await db.prepare(
    "SELECT last_seen FROM vbv_party_members WHERE id = ? AND party_code = ?"
  ).bind(party.host_member_id, code).first();
  if (!host || Number(host.last_seen) < now - PARTY_STALE_MS || Number(party.expires_at) < now) {
    await partyDelete(db, code);
    return null;
  }
  await db.prepare(
    "DELETE FROM vbv_party_members WHERE party_code = ? AND id != ? AND last_seen < ?"
  ).bind(code, party.host_member_id, now - PARTY_STALE_MS).run();
  return party;
}

async function partyAuthenticate(db, code, token) {
  if (!token || String(token).length > 256) return null;
  const hash = await partyTokenHash(token);
  return await db.prepare(
    "SELECT m.id, m.player_name, p.host_member_id FROM vbv_party_members m " +
    "JOIN vbv_parties p ON p.code = m.party_code " +
    "WHERE m.party_code = ? AND m.token_hash = ?"
  ).bind(code, hash).first();
}

async function partySnapshot(db, code, member) {
  const rows = await db.prepare(
    "SELECT id, player_name FROM vbv_party_members WHERE party_code = ? ORDER BY joined_at ASC"
  ).bind(code).all();
  return {
    ok: true,
    code,
    host: member.id === member.host_member_id,
    members: (rows.results || []).map((row) => ({
      id: row.id,
      name: row.player_name,
      host: row.id === member.host_member_id
    }))
  };
}

async function handlePartyRequest(request, env, url) {
  if (request.method === "OPTIONS") return partyResponse(request, { ok: true });
  if (request.method !== "POST") return partyResponse(request, { ok: false, error: "POST required" }, 405);
  if (!env.VBV_PARTIES) {
    return partyResponse(request, {
      ok: false,
      error: "party database is not configured; bind the Cloudflare D1 database as VBV_PARTIES"
    }, 503);
  }

  const allowedOrigins = String(env.RELAY_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  const origin = request.headers.get("origin") ?? "";
  if (allowedOrigins.length && !allowedOrigins.includes("*") && origin && !allowedOrigins.includes(origin)) {
    return partyResponse(request, { ok: false, error: "origin is not allowed" }, 403);
  }

  const db = env.VBV_PARTIES;
  const action = url.pathname.slice("/party/".length).replace(/\\/$/, "");
  const now = Date.now();
  try {
    const body = await partyBody(request);

    if (action === "create") {
      const name = partyName(body.name);
      let code = "";
      for (let attempt = 0; attempt < 8; attempt++) {
        const candidate = randomLANCode();
        const exists = await db.prepare("SELECT code FROM vbv_parties WHERE code = ?").bind(candidate).first();
        if (!exists) { code = candidate; break; }
      }
      if (!code) return partyResponse(request, { ok: false, error: "could not allocate a party code; try again" }, 503);
      const id = randomPeerId();
      const token = partyToken();
      const tokenHash = await partyTokenHash(token);
      await db.prepare(
        "INSERT INTO vbv_parties (code, host_member_id, created_at, updated_at, expires_at) VALUES (?, ?, ?, ?, ?)"
      ).bind(code, id, now, now, now + 6 * 60 * 60 * 1000).run();
      await db.prepare(
        "INSERT INTO vbv_party_members (id, party_code, player_name, token_hash, joined_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(id, code, name, tokenHash, now, now).run();
      return partyResponse(request, { ok: true, code, token, memberId: id, host: true, members: [{ id, name, host: true }] });
    }

    if (action === "join") {
      const code = partyCode(body.code);
      const name = partyName(body.name);
      const party = await partyCleanup(db, code, now);
      if (!party) return partyResponse(request, { ok: false, error: "party not found or its host has disconnected" }, 404);
      const count = await db.prepare("SELECT COUNT(*) AS count FROM vbv_party_members WHERE party_code = ?").bind(code).first();
      if (Number(count?.count || 0) >= PARTY_MAX_MEMBERS) {
        return partyResponse(request, { ok: false, error: "party is full" }, 409);
      }
      const duplicate = await db.prepare(
        "SELECT id FROM vbv_party_members WHERE party_code = ? AND lower(player_name) = lower(?)"
      ).bind(code, name).first();
      if (duplicate) return partyResponse(request, { ok: false, error: "that player is already in this party" }, 409);
      const id = randomPeerId();
      const token = partyToken();
      const tokenHash = await partyTokenHash(token);
      await db.prepare(
        "INSERT INTO vbv_party_members (id, party_code, player_name, token_hash, joined_at, last_seen) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(id, code, name, tokenHash, now, now).run();
      await db.prepare("UPDATE vbv_parties SET updated_at = ?, expires_at = ? WHERE code = ?")
        .bind(now, now + 6 * 60 * 60 * 1000, code).run();
      return partyResponse(request, { ok: true, code, token, memberId: id, host: false });
    }

    if (action === "poll" || action === "leave" || action === "kick" || action === "disband") {
      const code = partyCode(body.code);
      const party = await partyCleanup(db, code, now);
      if (!party) return partyResponse(request, { ok: false, error: "party has ended" }, 404);
      const member = await partyAuthenticate(db, code, body.token);
      if (!member) return partyResponse(request, { ok: false, error: "party session is invalid; rejoin using the code" }, 401);

      if (action === "poll") {
        await db.prepare("UPDATE vbv_party_members SET last_seen = ? WHERE id = ?").bind(now, member.id).run();
        await db.prepare("UPDATE vbv_parties SET updated_at = ?, expires_at = ? WHERE code = ?")
          .bind(now, now + 6 * 60 * 60 * 1000, code).run();
        return partyResponse(request, await partySnapshot(db, code, member));
      }

      if (action === "leave") {
        if (member.id === member.host_member_id) {
          await partyDelete(db, code);
          return partyResponse(request, { ok: true, ended: true });
        }
        await db.prepare("DELETE FROM vbv_party_members WHERE id = ?").bind(member.id).run();
        const count = await db.prepare("SELECT COUNT(*) AS count FROM vbv_party_members WHERE party_code = ?").bind(code).first();
        if (Number(count?.count || 0) === 0) await partyDelete(db, code);
        return partyResponse(request, { ok: true, ended: false });
      }

      if (action === "disband") {
        if (member.id !== member.host_member_id) return partyResponse(request, { ok: false, error: "only the party host can disband the party" }, 403);
        await partyDelete(db, code);
        return partyResponse(request, { ok: true, ended: true });
      }

      if (action === "kick") {
        if (member.id !== member.host_member_id) return partyResponse(request, { ok: false, error: "only the party host can kick players" }, 403);
        const targetId = String(body.memberId ?? "");
        if (!targetId || targetId === member.host_member_id) return partyResponse(request, { ok: false, error: "invalid kick target" }, 400);
        const target = await db.prepare(
          "SELECT id FROM vbv_party_members WHERE id = ? AND party_code = ?"
        ).bind(targetId, code).first();
        if (!target) return partyResponse(request, { ok: false, error: "player is no longer in this party" }, 404);
        await db.prepare("DELETE FROM vbv_party_members WHERE id = ?").bind(targetId).run();
        return partyResponse(request, { ok: true });
      }
    }

    return partyResponse(request, { ok: false, error: "unknown party action" }, 404);
  } catch (error) {
    return partyResponse(request, { ok: false, error: error instanceof Error ? error.message : "party request failed" }, 400);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const publicAccess = String(env.RELAY_PUBLIC ?? "") === "1";
    if (url.pathname === "/party" || url.pathname.startsWith("/party/")) {
      return handlePartyRequest(request, env, url);
    }
    if (url.pathname === "/health") {
      return Response.json({
        ok: true,
        protocol: "minecraft-java-byte-stream-v1",
        lan: "eagler-1.8-webrtc-p2p-durable-object-v1",
        capabilities: ["singleplayer", "multiplayer"],
        public: publicAccess,
        runtime: "cloudflare",
        minecraftRuntime: String(env.RELAY_MINECRAFT_UPSTREAM ?? "").trim()
          ? "websocket-upstream"
          : "durable-object"
      });
    }
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return errorResponse(404, "not found");
    }

    try {
      const allowedOrigins = String(env.RELAY_ALLOWED_ORIGINS ?? "").split(",").map((value) => value.trim()).filter(Boolean);
      const origin = request.headers.get("origin") ?? "";
      if (allowedOrigins.length && !allowedOrigins.includes(origin)) throw new Error("origin is not allowed");
      if (url.pathname === "/" || url.pathname === "") {
        const id = env.LAN_ROOMS.idFromName("global");
        return env.LAN_ROOMS.get(id).fetch(request);
      }
      if (url.pathname !== "/minecraft") {
        return errorResponse(404, "not found");
      }
      const target = parseTarget(url.searchParams.get("target"));
      if (isPrivateTarget(target.host)) throw new Error("private destinations are disabled");
      if (!publicAccess) {
        await verifyToken(env.RELAY_SECRET, url.searchParams.get("token"), target.canonical);
      }
      if (String(env.RELAY_MINECRAFT_UPSTREAM ?? "").trim()) {
        return openMinecraftUpstream(request, env);
      }
      const id = env.MINECRAFT_TUNNELS.newUniqueId();
      return env.MINECRAFT_TUNNELS.get(id).fetch(request);
    } catch (error) {
      return errorResponse(401, error instanceof Error ? error.message : "relay rejected");
    }
  }
};

export class MinecraftTunnel {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
    this.webSocket = null;
    this.tcp = null;
    this.writer = null;
    this.reader = null;
    this.target = null;
    this.accepted = false;
    this.pending = [];
    this.pendingBytes = 0;
    this.messageChain = Promise.resolve();
    this.windowStarted = Date.now();
    this.windowBytes = 0;
    this.closed = false;
    this.closePromise = null;
    this.opened = Promise.resolve(false);
    this.lifetimeTimer = null;
    this.traceId = [...crypto.getRandomValues(new Uint8Array(4))]
      .map((value) => value.toString(16).padStart(2, "0")).join("");
  }

  async fetch(request) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return errorResponse(426, "websocket required");
    }
    if (this.webSocket !== null || this.tcp !== null) {
      return errorResponse(409, "relay tunnel is already in use");
    }

    try {
      const url = new URL(request.url);
      this.target = parseTarget(url.searchParams.get("target"));
      if (isPrivateTarget(this.target.host)) throw new Error("private destinations are disabled");
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.webSocket = server;
      server.serializeAttachment({ target: this.target.canonical, created: Date.now() });
      this.ctx.acceptWebSocket(server);
      this.opened = this.openTcp();
      this.ctx.waitUntil(this.opened);
      const maxLifetimeMs = Number(this.env.RELAY_MAX_LIFETIME_MS ?? 0);
      if (Number.isFinite(maxLifetimeMs) && maxLifetimeMs > 0) {
        this.lifetimeTimer = setTimeout(
          () => void this.close(1000, "connection lifetime reached"),
          maxLifetimeMs
        );
      }
      return new Response(null, { status: 101, webSocket: client });
    } catch (error) {
      await this.close(1008, "relay rejected");
      return errorResponse(401, error instanceof Error ? error.message : "relay rejected");
    }
  }

  async openTcp() {
    const destination = await resolveMinecraftDestination(this.target, this.env);
    if (this.closed) return false;
    if (isPrivateTarget(destination.host)) {
      await this.close(1008, "private destinations are disabled");
      return false;
    }
    try {
      const socket = connect({ hostname: destination.host, port: destination.port }, { allowHalfOpen: true });
      this.tcp = socket;
      await socket.opened;
      if (this.closed) {
        await socket.close();
        return false;
      }
      this.writer = socket.writable.getWriter();
      this.ctx.waitUntil(this.pumpTcpToWebSocket(socket));
      return true;
    } catch {
      await this.close(1011, `Could not connect to ${this.target.canonical}`);
      return false;
    }
  }

  webSocketMessage(socket, message) {
    if (this.closed) return;
    this.webSocket = socket;
    this.messageChain = this.messageChain.then(async () => {
      const bytes = await normalizeBinaryData(message);
      if (this.closed) return;
      if (bytes === null) {
        await this.close(1003, "binary frames required");
        return;
      }
      if (!await this.opened || this.closed) return;

      const now = Date.now();
      if (now - this.windowStarted >= 60000) {
        this.windowStarted = now;
        this.windowBytes = 0;
      }
      this.windowBytes += bytes.byteLength;
      const maxBytesPerMinute = Number(this.env.RELAY_MAX_BYTES_PER_MINUTE ?? 64 * 1024 * 1024);
      if (this.windowBytes > maxBytesPerMinute) {
        await this.close(1008, "rate limit exceeded");
        return;
      }

      let outgoing = bytes;
      if (!this.accepted) {
        this.pending.push(bytes.slice());
        this.pendingBytes += bytes.byteLength;
        if (this.pendingBytes > MAX_HANDSHAKE_BYTES) {
          await this.close(1008, "handshake too large");
          return;
        }
        outgoing = concatBytes(this.pending, this.pendingBytes);
        const result = validateMinecraftHandshake(outgoing);
        if (result.status === "invalid") {
          await this.close(1008, result.reason);
          return;
        }
        if (result.status === "more") return;
        if (result.port !== this.target.port) {
          await this.close(1008, "handshake target port mismatch");
          return;
        }
        this.accepted = true;
        this.pending = [];
        this.pendingBytes = 0;
      }
      await this.writer.write(outgoing);
    }).catch(() => this.close(1011, "target write failed"));
    return this.messageChain;
  }

  webSocketClose(socket, code, reason, wasClean) {
    this.webSocket = socket;
    return this.close(webSocketCloseCode(code, 1000),
      reason || (wasClean ? "client closed" : "client connection dropped"));
  }

  webSocketError(socket) {
    this.webSocket = socket;
    return this.close(1011, "websocket failed");
  }

  async pumpTcpToWebSocket(socket) {
    const reader = socket.readable.getReader();
    this.reader = reader;
    try {
      while (!this.closed) {
        const { value, done } = await reader.read();
        if (done) break;
        if (!this.closed && value?.byteLength && this.webSocket?.readyState === WebSocket.OPEN) {
          this.webSocket.send(value);
        }
      }
      await this.close(1000, "target closed");
    } catch {
      await this.close(1011, "target read failed");
    } finally {
      if (this.reader === reader) this.reader = null;
      try { reader.releaseLock(); } catch {}
    }
  }

  close(code = 1011, reason = "relay closed") {
    if (this.closePromise) return this.closePromise;
    this.closed = true;
    if (this.lifetimeTimer !== null) clearTimeout(this.lifetimeTimer);
    code = webSocketCloseCode(code);
    const wireReason = webSocketCloseReason(reason);
    if (code !== 1000 && this.target !== null) {
      console.warn(`[minecraft-relay:${this.traceId}] ${this.target.canonical} close code=${code} reason=${wireReason}`);
    }
    this.closePromise = (async () => {
      try { this.webSocket?.close(code, wireReason); } catch {}
      const reader = this.reader;
      this.reader = null;
      try { await reader?.cancel(wireReason); } catch {}
      try { this.writer?.releaseLock(); } catch {}
      this.writer = null;
      try { await this.tcp?.close(); } catch {}
      this.tcp = null;
    })();
    return this.closePromise;
  }
}

export class LanRoom {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") {
      return errorResponse(426, "websocket required");
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({ role: "pending", created: Date.now() });
    this.ctx.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  sockets() {
    return this.ctx.getWebSockets();
  }

  attachment(socket) {
    try { return socket.deserializeAttachment() ?? { role: "pending" }; }
    catch { return { role: "pending" }; }
  }

  findHost(code) {
    return this.sockets().find((socket) => {
      const state = this.attachment(socket);
      return state.role === "host" && state.code === code && socket.readyState === WebSocket.OPEN;
    }) ?? null;
  }

  findGuest(code, id) {
    return this.sockets().find((socket) => {
      const state = this.attachment(socket);
      return state.role === "guest" && state.code === code && state.id === id && socket.readyState === WebSocket.OPEN;
    }) ?? null;
  }

  guests(code) {
    return this.sockets().filter((socket) => {
      const state = this.attachment(socket);
      return state.role === "guest" && state.code === code && socket.readyState === WebSocket.OPEN;
    });
  }

  send(socket, bytes) {
    if (!socket || socket.readyState !== WebSocket.OPEN) return false;
    try { socket.send(bytes); return true; } catch { return false; }
  }

  reject(socket, errorCode, reason, closeCode = 1008) {
    this.send(socket, errorPacket(errorCode, reason));
    try { socket.close(closeCode, reason.slice(0, 120)); } catch {}
  }

  parseASCII8(bytes, offset) {
    if (offset >= bytes.length) throw new Error("truncated ASCII8 field");
    const length = bytes[offset++];
    if (offset + length > bytes.length) throw new Error("truncated ASCII8 data");
    return { value: String.fromCharCode(...bytes.subarray(offset, offset + length)), offset: offset + length };
  }

  parseASCII16(bytes, offset) {
    if (offset + 2 > bytes.length) throw new Error("truncated ASCII16 field");
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    offset += 2;
    if (offset + length > bytes.length) throw new Error("truncated ASCII16 data");
    return { value: String.fromCharCode(...bytes.subarray(offset, offset + length)), offset: offset + length };
  }

  parsePeerPayload(bytes) {
    const peer = this.parseASCII8(bytes, 1);
    if (peer.offset + 2 > bytes.length) throw new Error("truncated payload length");
    const length = (bytes[peer.offset] << 8) | bytes[peer.offset + 1];
    const offset = peer.offset + 2;
    if (offset + length !== bytes.length) throw new Error("invalid payload length");
    return { peer: peer.value, payload: bytes.subarray(offset) };
  }

  forwardPeerPayload(target, type, peer, payload) {
    this.send(target, packet([Uint8Array.of(type), ascii8(peer),
      Uint8Array.of(payload.length >>> 8, payload.length & 255), payload]));
  }

  async webSocketMessage(socket, message) {
    const bytes = await normalizeBinaryData(message);
    if (bytes === null || bytes.byteLength === 0 || bytes.byteLength > 65536) {
      this.reject(socket, 2, "Binary relay packet required", 1003);
      return;
    }
    try {
      const state = this.attachment(socket);
      if (state.role === "pending") {
        this.handleHandshake(socket, bytes);
      } else if (state.role === "host") {
        this.handleHost(socket, state, bytes);
      } else if (state.role === "guest") {
        this.handleGuest(socket, state, bytes);
      } else {
        this.reject(socket, 3, "Invalid relay session state");
      }
    } catch (error) {
      this.reject(socket, 2, error instanceof Error ? error.message : "Invalid relay packet");
    }
  }

  handleHandshake(socket, bytes) {
    if (bytes[0] !== 0x00 || bytes.length < 4) throw new Error("Expected handshake packet");
    const connectionType = bytes[1];
    const protocolVersion = bytes[2];
    const codeField = this.parseASCII8(bytes, 3);
    if (codeField.offset !== bytes.length) throw new Error("Trailing handshake data");
    if (protocolVersion !== 1) {
      this.reject(socket, 1, "Unsupported relay protocol version; version 1 required");
      return;
    }
    if (connectionType === 0x03) {
      this.send(socket, pongPacket());
      socket.close(1000, "pong");
      return;
    }
    if (connectionType === 0x01) {
      let code;
      for (let attempt = 0; attempt < 32; ++attempt) {
        code = randomLANCode();
        if (!this.findHost(code)) break;
        code = null;
      }
      if (!code) {
        this.reject(socket, 0, "Relay has no available join codes", 1013);
        return;
      }
      socket.serializeAttachment({ role: "host", code, created: Date.now() });
      this.send(socket, handshakePacket(0x01, code));
      this.send(socket, iceServersPacket(this.env));
      return;
    }
    if (connectionType === 0x02) {
      const code = codeField.value.toUpperCase();
      if (!LAN_CODE_RE.test(code)) {
        this.reject(socket, 4, "Join code must be 6 letters or digits");
        return;
      }
      const host = this.findHost(code);
      if (!host) {
        this.reject(socket, 5, "Invalid code, no LAN world found");
        return;
      }
      if (this.guests(code).length >= Number(this.env.RELAY_MAX_LAN_PEERS ?? 8)) {
        this.reject(socket, 0, "LAN world is full", 1013);
        return;
      }
      let id;
      do id = randomPeerId(); while (this.findGuest(code, id));
      socket.serializeAttachment({ role: "guest", code, id, stage: 0, completed: false, created: Date.now() });
      this.send(socket, handshakePacket(0x02, id));
      this.send(host, packet([Uint8Array.of(0x02), ascii8(id)]));
      this.send(socket, iceServersPacket(this.env));
      return;
    }
    this.reject(socket, 3, "Unsupported relay connection type");
  }

  handleHost(socket, state, bytes) {
    const type = bytes[0];
    if (type === 0x03 || type === 0x04) {
      const parsed = this.parsePeerPayload(bytes);
      const guest = this.findGuest(state.code, parsed.peer);
      if (!guest) {
        this.send(socket, errorPacket(7, `Unknown Client ID: ${parsed.peer}`));
        return;
      }
      const guestState = this.attachment(guest);
      guestState.stage = type === 0x04 ? 2 : 4;
      guest.serializeAttachment(guestState);
      this.forwardPeerPayload(guest, type, "", parsed.payload);
      return;
    }
    if (type === 0xfe) {
      let field = this.parseASCII8(bytes, 1);
      const guest = this.findGuest(state.code, field.value);
      if (!guest) return;
      this.send(guest, bytes);
      try { guest.close(1000, "host ended signaling"); } catch {}
      return;
    }
    throw new Error("Host sent an unexpected relay packet");
  }

  handleGuest(socket, state, bytes) {
    const host = this.findHost(state.code);
    if (!host) {
      this.reject(socket, 6, "LAN host disconnected");
      return;
    }
    const type = bytes[0];
    if (type === 0x03 || type === 0x04) {
      const parsed = this.parsePeerPayload(bytes);
      if (parsed.peer !== "") throw new Error("Guest packet contained a client ID");
      if (type === 0x04 && state.stage !== 0) throw new Error("Unexpected guest description");
      if (type === 0x03 && state.stage !== 2) throw new Error("Unexpected guest ICE candidate");
      state.stage = type === 0x04 ? 1 : 3;
      socket.serializeAttachment(state);
      this.forwardPeerPayload(host, type, state.id, parsed.payload);
      return;
    }
    if (type === 0x05 || type === 0x06) {
      const field = this.parseASCII8(bytes, 1);
      if (field.offset !== bytes.length || field.value !== "") throw new Error("Invalid guest completion packet");
      if (state.stage !== 4) throw new Error("Guest completed signaling out of order");
      state.completed = true;
      socket.serializeAttachment(state);
      this.send(host, packet([Uint8Array.of(type), ascii8(state.id)]));
      this.send(socket, disconnectPacket(state.id, type === 0x05 ? 0 : 1,
        type === 0x05 ? "Successful connection" : "Failed connection"));
      try { socket.close(1000, "signaling complete"); } catch {}
      return;
    }
    throw new Error("Guest sent an unexpected relay packet");
  }

  async webSocketClose(socket, code, reason) {
    this.handleSocketGone(socket, code, reason || "connection closed");
  }

  async webSocketError(socket, error) {
    this.handleSocketGone(socket, 1011, error instanceof Error ? error.message : "WebSocket error");
  }

  handleSocketGone(socket, closeCode, reason) {
    const state = this.attachment(socket);
    if (state.role === "host") {
      for (const guest of this.guests(state.code)) {
        this.send(guest, errorPacket(6, "LAN host disconnected"));
        try { guest.close(1011, "LAN host disconnected"); } catch {}
      }
      console.warn(`[p2p] host ${state.code} disconnected code=${closeCode} reason=${reason}`);
    } else if (state.role === "guest" && !state.completed) {
      const host = this.findHost(state.code);
      this.send(host, disconnectPacket(state.id, 0xff, reason || "End of stream"));
    }
    try { socket.close(closeCode || 1000, String(reason || "closed").slice(0, 120)); } catch {}
  }
}
