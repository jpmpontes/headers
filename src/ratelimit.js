'use strict';

/** Rate limit em memória (janela deslizante) por chave, normalmente o IP do cliente. */
class RateLimiter {
  constructor({ max = 10, windowMs = 60_000 } = {}) {
    this.max = max;
    this.windowMs = windowMs;
    this.hits = new Map();
    this.sweeper = setInterval(() => this.sweep(), Math.max(1000, windowMs));
    this.sweeper.unref();
  }

  /** Registra uma tentativa. Retorna { ok, retryAfterSec }. */
  hit(key, now = Date.now()) {
    const from = now - this.windowMs;
    const list = (this.hits.get(key) || []).filter((t) => t > from);
    if (list.length >= this.max) {
      this.hits.set(key, list);
      return { ok: false, retryAfterSec: Math.max(1, Math.ceil((list[0] + this.windowMs - now) / 1000)) };
    }
    list.push(now);
    this.hits.set(key, list);
    return { ok: true, retryAfterSec: 0 };
  }

  sweep(now = Date.now()) {
    const from = now - this.windowMs;
    for (const [key, list] of this.hits) {
      const fresh = list.filter((t) => t > from);
      if (fresh.length) this.hits.set(key, fresh);
      else this.hits.delete(key);
    }
  }

  close() {
    clearInterval(this.sweeper);
  }
}

module.exports = { RateLimiter };
