# Eaglercraft 26.2 Web Socket Relay

A small WebSocket relay for Eaglercraft 26.2. It supports Minecraft Java connections and Eaglercraft 1.8 LAN signaling.

## What it does

- `/minecraft` forwards Minecraft Java traffic.
- `/` relays Eaglercraft 1.8 LAN signaling. World traffic remains peer-to-peer over WebRTC.

## Run it locally or on a VPS

Requirements: Node.js 20 or newer.

```bash
npm ci
RELAY_PUBLIC=1 npm start
```

The server listens on port `8787` by default. Use `ws://host:8787` locally, or place it behind HTTPS and use `wss://relay.example.com`.

### Public mode

Public mode accepts tokenless Minecraft connections:

```bash
RELAY_PUBLIC=1 npm start
```

### Private mode

Private mode requires a shared secret:

```bash
RELAY_PUBLIC=0 RELAY_SECRET='use-a-long-random-secret' npm start
```

Create a Minecraft server token:

```bash
RELAY_SECRET="$RELAY_SECRET" npm run token -- server.example.com:25565 3600
```

Create a LAN host token:

```bash
RELAY_SECRET="$RELAY_SECRET" npm run token -- --lan-host 21600
```

Do not enable `RELAY_ALLOW_PRIVATE` on a public relay.

## Clone from Radicle

This project is hosted publicly on Radicle:

```bash
rad clone rad:z3FV98H1Sqkbmrtg2P4QyCgogJS4C
```

Browse it in the [Radicle Explorer](https://radicle.network/nodes/iris.radicle.network/rad:z3FV98H1Sqkbmrtg2P4QyCgogJS4C).

## Standalone client

The Node relay can serve the standalone client from `http://127.0.0.1:8787/`. By default it looks for `../eaglercraft-26.2-single.html`.

To use a different client file:

```bash
RELAY_CLIENT_HTML=/absolute/path/to/client.html RELAY_PUBLIC=1 npm start
```

## Docker

```bash
docker build -t eagler-relay .
docker run --rm -p 8787:8787 -e RELAY_PUBLIC=1 eagler-relay
```

## Cloudflare Worker

The current public Worker is:

```text
wss://eagler-minecraft-relay.u2471966200.workers.dev
```

Add this base URL to the client relay list and choose `Both`. The client uses `/minecraft` for Java servers and the root WebSocket for LAN signaling.

Deploy the Worker with Wrangler:

```bash
npm ci
npx wrangler login
npm run deploy
```

By default, Minecraft connections use one Durable Object per session. LAN uses a hibernating Durable Object for WebRTC signaling.

To forward Minecraft connections to a private HTTPS Node relay, store the upstream URL as a secret rather than committing it:

```bash
npx wrangler secret put RELAY_MINECRAFT_UPSTREAM --config cloudflare/wrangler.toml
npm run deploy
```

For private Worker mode, change `RELAY_PUBLIC` to `"0"` in `cloudflare/wrangler.toml`, then store `RELAY_SECRET` and deploy again:

```bash
npx wrangler secret put RELAY_SECRET --config cloudflare/wrangler.toml
npm run deploy
```

## Configuration

- `RELAY_ALLOWED_ORIGINS` — comma-separated browser origins
- `RELAY_MAX_BYTES_PER_MINUTE` — per-connection byte limit
- `RELAY_MAX_LIFETIME_MS` — optional connection lifetime; `0` disables it
- `RELAY_MAX_LAN_PEERS` — maximum guests in a LAN room
- `RELAY_ICE_SERVERS` — comma-separated STUN/TURN servers
- `RELAY_MINECRAFT_UPSTREAM` — optional private HTTPS relay for Minecraft passthrough
- `RELAY_DNS_HTTPS` — DNS-over-HTTPS endpoint used for Minecraft SRV records
- `RELAY_ALLOW_PRIVATE` — allows private TCP targets on a trusted local relay
- `RELAY_CLIENT_HTML` — standalone client file served by the Node relay
- `RELAY_MEMORY_LIMIT_BYTES` — memory limit override
- `RELAY_MEMORY_HIGH_WATERMARK` — memory pressure threshold
- `RELAY_CPU_HIGH_WATERMARK` — CPU pressure threshold
- `RELAY_EVENT_LOOP_HIGH_MS` — event-loop delay threshold
- `RELAY_HEARTBEAT_MS` — WebSocket heartbeat interval

## Development checks

```bash
npm audit --omit=dev
npx wrangler deploy --dry-run --config cloudflare/wrangler.toml
```

## License

MIT.
