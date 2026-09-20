import os from "node:os";
import { readFileSync } from "node:fs";
import { monitorEventLoopDelay } from "node:perf_hooks";

export const OVERLOAD_MESSAGE = "Relay overloaded. Please wait and try again.";

const MIB = 1024 * 1024;

function number(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function readLimit(path) {
  try {
    const value = readFileSync(path, "utf8").trim();
    if (!value || value === "max") return Infinity;
    const parsed = Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : Infinity;
  } catch {
    return Infinity;
  }
}

export function detectMemoryLimit() {
  return Math.min(
    os.totalmem(),
    readLimit("/sys/fs/cgroup/memory.max"),
    readLimit("/sys/fs/cgroup/memory/memory.limit_in_bytes")
  );
}

export class AdaptiveAdmission {
  constructor(options = {}) {
    this.memoryLimit = number(options.memoryLimitBytes ?? process.env.RELAY_MEMORY_LIMIT_BYTES, detectMemoryLimit());
    this.highMemoryRatio = number(options.highMemoryRatio ?? process.env.RELAY_MEMORY_HIGH_WATERMARK, 0.82);
    this.lowMemoryRatio = Math.min(this.highMemoryRatio - 0.02, number(options.lowMemoryRatio ?? process.env.RELAY_MEMORY_LOW_WATERMARK, 0.72));
    this.highCpuRatio = number(options.highCpuRatio ?? process.env.RELAY_CPU_HIGH_WATERMARK, 0.9);
    this.lowCpuRatio = Math.min(this.highCpuRatio - 0.05, number(options.lowCpuRatio ?? process.env.RELAY_CPU_LOW_WATERMARK, 0.7));
    this.highLagMs = number(options.highLagMs ?? process.env.RELAY_EVENT_LOOP_HIGH_MS, 120);
    this.lowLagMs = Math.min(this.highLagMs - 5, number(options.lowLagMs ?? process.env.RELAY_EVENT_LOOP_LOW_MS, 60));
    this.getRss = options.getRss ?? (() => process.memoryUsage.rss());
    this.getCpuUsage = options.getCpuUsage ?? (() => process.cpuUsage());
    this.now = options.now ?? (() => process.hrtime.bigint());
    this.active = 0;
    this.overloaded = false;
    this.pressureSamples = 0;
    this.recoverySamples = 0;
    this.rss = this.getRss();
    this.baselineRss = this.rss;
    this.cpuRatio = 0;
    this.lagMs = 0;
    this.lastCpu = this.getCpuUsage();
    this.lastTime = this.now();
    this.loop = options.monitorEventLoop === false ? null : monitorEventLoopDelay({ resolution: 20 });
    this.loop?.enable();
    const intervalMs = options.sampleIntervalMs === 0 ? 0 : number(options.sampleIntervalMs, 1000);
    this.timer = intervalMs ? setInterval(() => this.sample(), intervalMs) : null;
    this.timer?.unref?.();
  }

  sample() {
    this.rss = this.getRss();
    const now = this.now();
    const cpu = this.getCpuUsage();
    const elapsed = Number(now - this.lastTime) / 1000;
    const used = cpu.user + cpu.system - this.lastCpu.user - this.lastCpu.system;
    if (elapsed > 0) this.cpuRatio = Math.max(0, used / elapsed);
    this.lastTime = now;
    this.lastCpu = cpu;
    if (this.loop) {
      const lag = this.loop.percentile(99) / 1e6;
      this.lagMs = Number.isFinite(lag) ? lag : 0;
      this.loop.reset();
    }
    const memoryRatio = this.rss / this.memoryLimit;
    const pressure = memoryRatio >= this.highMemoryRatio
      || (this.active > 0 && (this.cpuRatio >= this.highCpuRatio || this.lagMs >= this.highLagMs));
    const recovered = memoryRatio <= this.lowMemoryRatio
      && this.cpuRatio <= this.lowCpuRatio
      && this.lagMs <= this.lowLagMs;
    if (pressure) {
      this.pressureSamples += 1;
      this.recoverySamples = 0;
      if (memoryRatio >= this.highMemoryRatio || this.pressureSamples >= 2) this.overloaded = true;
    } else {
      this.pressureSamples = 0;
      if (recovered) this.recoverySamples += 1;
      else this.recoverySamples = 0;
      if (this.recoverySamples >= 3) this.overloaded = false;
    }
    return this.snapshot();
  }

  tryAcquire() {
    this.rss = this.getRss();
    const highMemory = this.memoryLimit * this.highMemoryRatio;
    const usedByConnections = Math.max(0, this.rss - this.baselineRss);
    const estimatedConnection = this.active > 0
      ? Math.max(64 * 1024, usedByConnections / this.active)
      : 256 * 1024;
    if (this.overloaded || this.rss + estimatedConnection >= highMemory) {
      this.overloaded = true;
      return false;
    }
    this.active += 1;
    return true;
  }

  release() {
    this.active = Math.max(0, this.active - 1);
  }

  canBuffer(socket, incomingBytes = 0) {
    const headroom = Math.max(0, this.memoryLimit * this.highMemoryRatio - this.rss);
    const perConnection = headroom / Math.max(1, this.active);
    const allowance = Math.max(256 * 1024, Math.min(8 * MIB, perConnection / 4));
    return this.rss < this.memoryLimit * this.highMemoryRatio
      && socket.bufferedAmount + incomingBytes <= allowance;
  }

  snapshot() {
    return {
      connections: this.active,
      overloaded: this.overloaded,
      rssMiB: Math.round(this.rss / MIB),
      memoryLimitMiB: Math.round(this.memoryLimit / MIB),
      cpuPercent: Math.round(this.cpuRatio * 100),
      eventLoopP99Ms: Math.round(this.lagMs)
    };
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.loop?.disable();
  }
}
