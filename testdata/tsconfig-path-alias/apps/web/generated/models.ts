// The FIRST target of `"@/*": ["./generated/*", "./*"]`, and the reason the array is
// ordered: `@/models` is answered here, while `@/lib/...` finds nothing under
// `generated/` and falls through to the second target.

export function describeModel(): string {
  return "link";
}
