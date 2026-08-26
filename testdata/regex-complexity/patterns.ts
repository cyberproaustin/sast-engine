// Two patterns that differ by one character, and the difference is the whole rule.
//
// Both repeat a class and then repeat a hyphen-separated group of the same class. In the
// first the hyphen is INSIDE the class, so a run like `a-a-a-a` can be divided between the
// `+` and the group in as many ways as it has hyphens, and a backtracking engine tries all
// of them before it fails. In the second the hyphen is not in the class, so every
// repetition of the group has exactly one place to begin and the match is linear.
//
// A rule that matched known-bad pattern strings, or that flagged nesting without reading
// the character sets, would report both. The second spelling is one of the commonest
// validation patterns there is.

// The shape umami ships and reaches before it authenticates.
export const HOSTNAME_LABEL = /^[a-z0-9-_]+(-[a-z0-9-_]+)*$/;

export const SAFE_LABEL = /^[a-zA-Z0-9]+(-[a-zA-Z0-9]+)*$/;
