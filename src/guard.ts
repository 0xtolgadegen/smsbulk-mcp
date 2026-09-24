/**
 * In-memory session guard — "Yol B" best-effort retry protection.
 *
 * 🔴 HONESTY: this is BEST-EFFORT, not guaranteed idempotency.
 *   - It lives only in this process's memory and resets on restart.
 *   - It does NOT coordinate across multiple clients/processes.
 *   - It cannot prevent a true server-side race.
 * Its only job is to catch the common accidental case: the same spending tool
 * (request_number / email_request) fired twice in one session with identical
 * arguments. The authoritative protections (balance, daily quota, rate limits)
 * are enforced server-side by the SMSBulk API.
 */
import { createHash } from "node:crypto";

export interface GuardResult<T> {
  value: T;
  /** true when this result was replayed from a prior identical call (no new spend). */
  deduped: boolean;
}

export class SessionGuard {
  private readonly inflight = new Map<string, Promise<unknown>>();
  private readonly settled = new Map<string, unknown>();

  /** Stable short fingerprint over the call's identity parts (undefined → ""). */
  fingerprint(parts: (string | undefined)[]): string {
    return createHash("sha256")
      .update(parts.map((p) => p ?? "").join("\u0000"))
      .digest("hex")
      .slice(0, 16);
  }

  /**
   * Run `fn` at most once per fingerprint for the life of this session.
   * A second call with the same fingerprint replays the first result instead of
   * invoking `fn` again. Errors are NOT cached, so a failed call can be retried.
   *
   * `beforeFresh` (if given) runs synchronously ONLY on the fresh path, just
   * before `fn` is invoked. Throwing from it aborts the spend without consuming
   * the fingerprint. It does not run for deduped replays (no new spend there).
   * It is synchronous so dedup remains atomic (no await before inflight is set).
   */
  async run<T>(fp: string, fn: () => Promise<T>, beforeFresh?: () => void): Promise<GuardResult<T>> {
    if (this.settled.has(fp)) {
      return { value: this.settled.get(fp) as T, deduped: true };
    }
    const existing = this.inflight.get(fp);
    if (existing) {
      // A concurrent call with the same fingerprint is already in flight.
      return { value: (await existing) as T, deduped: true };
    }
    if (beforeFresh) beforeFresh(); // sync; may throw to abort the fresh spend
    const p = fn();
    this.inflight.set(fp, p);
    try {
      const value = await p;
      this.settled.set(fp, value);
      return { value, deduped: false };
    } finally {
      this.inflight.delete(fp);
    }
  }
}
