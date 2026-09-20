import http from "node:http";
import net from "node:net";
import dns from "node:dns/promises";
import { createReadStream, existsSync, statSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { WebSocketServer } from "ws";
import { AdaptiveAdmission, OVERLOAD_MESSAGE } from "./admission.js";
import { verifyScopedToken, verifyToken } from "./auth.js";
import { LanRoomRegistry } from "./lan-rooms.js";
import { concatBytes, isPrivateTarget, parseTarget, selectSrvRecord, validateMinecraftHandshake } from "./protocol.js";

const MAX_HANDSHAKE_BYTES = 65536;

function rejectUpgrade(socket, status, message) {
  const body = `${message}\n`;
  socket.end(`HTTP/1.1 ${status}\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
}

async function assertPublicDestination(host, allowPrivate) {
  if (allowPrivate) return;
  if (isPrivateTarget(host)) throw new Error("private destinations are disabled");
  const addresses = await dns.lookup(host, { all: true, verbatim: true });
  if (addresses.length === 0 || addresses.some(({ address }) => isPrivateTarget(address))) {
    throw new Error("target resolves to a private destination");
  }
}

export async function resolveMinecraftDestination(target, resolveSrv = dns.resolveSrv) {
  if (target.explicitPort) return { host: target.host, port: target.port, viaSrv: false };
  try {
    const record = selectSrvRecord(await resolveSrv(`_minecraft._tcp.${target.host}`));
    if (record) return { host: record.name, port: record.port, viaSrv: true };
  } catch {}
  return { host: target.host, port: target.port, viaSrv: false };
}

export function createRelayServer(options = {}) {
  const secret = options.secret ?? process.env.RELAY_SECRET;
  const publicAccess = options.publicAccess ?? process.env.RELAY_PUBLIC === "1";
  const allowPrivate = options.allowPrivate ?? process.env.RELAY_ALLOW_PRIVATE === "1";
  const allowedOrigins = String(options.allowedOrigins ?? process.env.RELAY_ALLOWED_ORIGINS ?? "")
    .split(",").map((value) => value.trim()).filter(Boolean);
  const maxBytesPerMinute = Number(options.maxBytesPerMinute ?? process.env.RELAY_MAX_BYTES_PER_MINUTE ?? 64 * 1024 * 1024);
  const maxLanBytesPerMinute = Number(options.maxLanBytesPerMinute ?? process.env.RELAY_MAX_LAN_BYTES_PER_MINUTE ?? 512 * 1024 * 1024);
  const maxLifetimeMs = Number(options.maxLifetimeMs ?? process.env.RELAY_MAX_LIFETIME_MS ?? 6 * 60 * 60 * 1000);
  const maxLanPeers = Number(options.maxLanPeers ?? process.env.RELAY_MAX_LAN_PEERS ?? 8);
  const traceConnections = options.traceConnections ?? process.env.RELAY_TRACE === "1";
  const clientHtml = options.clientHtml ?? process.env.RELAY_CLIENT_HTML ?? "";
  const heartbeatMs = Number(options.heartbeatMs ?? process.env.RELAY_HEARTBEAT_MS ?? 25000);
  if (clientHtml) {
    try {
      statSync(clientHtml);
    } catch (error) {
      throw new Error(`standalone client is unavailable: ${error.message}`);
    }
  }
  if (!publicAccess && (!secret || secret.length < 16)) {
    throw new Error("RELAY_SECRET must be at least 16 characters unless RELAY_PUBLIC=1");
  }
  const admission = options.admission ?? new AdaptiveAdmission(options.admissionOptions);
  const ownsAdmission = !options.admission;

  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, "http://relay.invalid").pathname;
    if (clientHtml && (pathname === "/" || pathname === "/client" || pathname === "/eaglercraft-26.2-single.html")) {
      let clientHtmlSize;
      try {
        clientHtmlSize = statSync(clientHtml).size;
      } catch (error) {
        res.writeHead(503, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
        res.end(`standalone client is unavailable: ${error.message}\n`);
        return;
      }
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "content-length": clientHtmlSize,
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      });
      if (req.method === "HEAD") {
        res.end();
      } else {
        const stream = createReadStream(clientHtml);
        stream.on("error", () => res.destroy());
        stream.pipe(res);
      }
      return;
    }
    res.writeHead(pathname === "/health" ? 200 : 404, { "content-type": "application/json" });
    res.end(JSON.stringify(pathname === "/health"
      ? { ok: true, protocol: "minecraft-java-byte-stream-v1", lan: true, public: publicAccess, client: Boolean(clientHtml), load: admission.snapshot() }
      : { error: "not found" }));
  });
  const webSockets = new WebSocketServer({ noServer: true, maxPayload: 2 * 1024 * 1024, perMessageDeflate: false });
  const lanRooms = new LanRoomRegistry({
    maxPeers: maxLanPeers,
    maxLifetimeMs,
    maxBytesPerMinute: maxLanBytesPerMinute,
    canBuffer: (ws, bytes) => admission.canBuffer(ws, bytes),
    overloadMessage: OVERLOAD_MESSAGE
  });

  server.on("close", () => {
    if (ownsAdmission) admission.stop();
  });

  server.on("upgrade", async (request, socket, head) => {
    if (!admission.tryAcquire()) {
      webSockets.handleUpgrade(request, socket, head, (ws) => ws.close(1013, OVERLOAD_MESSAGE));
      return;
    }
    let transferred = false;
    try {
      const url = new URL(request.url, "http://relay.invalid");
      const origin = request.headers.origin ?? "";
      if (allowedOrigins.length && !allowedOrigins.includes(origin)) throw new Error("origin is not allowed");
      let metadata;
      if (url.pathname === "/minecraft") {
        const target = parseTarget(url.searchParams.get("target"));
        if (!publicAccess) {
          verifyToken(secret, url.searchParams.get("token"), target.canonical);
        }
        if (!allowPrivate && isPrivateTarget(target.host)) throw new Error("private destinations are disabled");
        const destination = await resolveMinecraftDestination(target);
        await assertPublicDestination(destination.host, allowPrivate);
        metadata = { mode: "minecraft", target, destination };
      } else if (url.pathname === "/lan/host") {
        if (!publicAccess) {
          verifyScopedToken(secret, url.searchParams.get("token"), "lan-host");
        }
        metadata = { mode: "lan-host" };
      } else if (url.pathname === "/lan/join") {
        const code = String(url.searchParams.get("code") ?? "").toUpperCase();
        if (!/^[A-HJ-NP-Z2-9]{6,10}$/.test(code)) {
          throw new Error("LAN room is unavailable");
        }
        metadata = { mode: "lan-join", code };
      } else {
        throw new Error("unknown relay path");
      }
      webSockets.handleUpgrade(request, socket, head, (ws) => {
        transferred = true;
        webSockets.emit("connection", ws, request, metadata);
      });
    } catch (error) {
      if (!transferred) admission.release();
      rejectUpgrade(socket, "401 Unauthorized", error.message);
    }
  });

  webSockets.on("connection", (ws, _request, metadata) => {
    let released = false;
    const heartbeat = setInterval(() => {
      if (ws.readyState === ws.OPEN) ws.ping();
    }, heartbeatMs);
    heartbeat.unref?.();
    ws.once("close", () => {
      clearInterval(heartbeat);
      if (released) return;
      released = true;
      admission.release();
    });
    if (metadata.mode === "lan-host") {
      lanRooms.acceptHost(ws);
      return;
    }
    if (metadata.mode === "lan-join") {
      lanRooms.acceptGuest(ws, metadata.code);
      return;
    }
    const target = metadata.target;
    const destination = metadata.destination;
    const traceId = Math.random().toString(36).slice(2, 8);
    const tcp = net.createConnection({ host: destination.host, port: destination.port });
    tcp.setNoDelay(true);
    tcp.setKeepAlive(true, 30000);
    let accepted = false;
    let pending = [];
    let pendingBytes = 0;
    let windowStarted = Date.now();
    let windowBytes = 0;
    let ended = false;
    let clientBytes = 0;
    let targetBytes = 0;

    const trace = (message) => {
      if (traceConnections) console.log(`[relay:${traceId}] ${target.canonical} ${message}`);
    };
    trace(destination.viaSrv ? `opening via=${destination.host}:${destination.port}` : "opening");

    const close = (code = 1011, reason = "relay closed") => {
      if (ended) return;
      ended = true;
      trace(`closing code=${code} reason=${reason} clientBytes=${clientBytes} targetBytes=${targetBytes}`);
      tcp.destroy();
      if (ws.readyState === ws.OPEN || ws.readyState === ws.CONNECTING) ws.close(code, reason.slice(0, 120));
    };
    const lifetime = setTimeout(() => close(1000, "connection lifetime reached"), maxLifetimeMs);
    lifetime.unref?.();

    ws.on("message", (data, isBinary) => {
      if (!isBinary) return close(1003, "binary frames required");
      const now = Date.now();
      if (now - windowStarted >= 60000) {
        windowStarted = now;
        windowBytes = 0;
      }
      windowBytes += data.byteLength;
      if (windowBytes > maxBytesPerMinute) return close(1008, "rate limit exceeded");
      const bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
      clientBytes += bytes.byteLength;
      if (!accepted) {
        pending.push(bytes.slice());
        pendingBytes += bytes.byteLength;
        if (pendingBytes > MAX_HANDSHAKE_BYTES) return close(1008, "handshake too large");
        const buffered = concatBytes(pending, pendingBytes);
        const result = validateMinecraftHandshake(buffered);
        if (result.status === "invalid") return close(1008, result.reason);
        if (result.status === "more") return;
        if (result.port !== target.port) return close(1008, "handshake target port mismatch");
        trace(`handshake protocol=${result.protocol} state=${result.nextState} host=${result.host} port=${result.port} bytes=${buffered.byteLength}`);
        accepted = true;
        pending = [];
        tcp.write(buffered);
      } else if (!tcp.write(bytes)) {
        ws._socket?.pause();
      }
    });
    tcp.on("drain", () => ws._socket?.resume());
    tcp.on("data", (data) => {
      if (targetBytes === 0) trace(`first response bytes=${data.byteLength} hex=${data.subarray(0, 96).toString("hex")}`);
      targetBytes += data.byteLength;
      if (!admission.canBuffer(ws, data.byteLength)) return close(1013, OVERLOAD_MESSAGE);
      if (ws.readyState === ws.OPEN) ws.send(data, { binary: true });
    });
    tcp.on("connect", () => trace("connected"));
    tcp.on("error", (error) => {
      trace(`target error=${error.code ?? error.message}`);
      close(1011, `Could not connect to ${target.canonical}`);
    });
    tcp.on("close", () => close(1000, "target closed"));
    ws.on("error", () => close());
    ws.on("close", () => {
      clearTimeout(lifetime);
      if (!ended) {
        ended = true;
        tcp.destroy();
      }
    });
  });

  return server;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 8787);
  const defaultClientHtml = fileURLToPath(new URL("../../eaglercraft-26.2-single.html", import.meta.url));
  const clientHtml = process.env.RELAY_CLIENT_HTML ?? (existsSync(defaultClientHtml) ? defaultClientHtml : "");
  const server = createRelayServer({ clientHtml });
  server.listen(port, process.env.HOST ?? "0.0.0.0", () => {
    console.log(`Minecraft relay + standalone client listening on http://127.0.0.1:${port}/`);
  });
}
