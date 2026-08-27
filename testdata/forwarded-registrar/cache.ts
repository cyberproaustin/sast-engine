// NEGATIVE — the method name is a verb and the call takes two arguments, which is the
// whole of what a route registration looks like from outside. What tells them apart is
// that this `get` does not forward anything to a registration: nothing in its body
// describes a route.
export class Cache {
  private entries = new Map<string, string>();

  get(key: string, fallback: string): string {
    return this.entries.get(key) ?? fallback;
  }

  post(key: string, value: string): void {
    this.entries.set(key, value);
  }
}

export function readThrough(cache: Cache, key: string): string {
  return cache.get(key, "missing");
}
