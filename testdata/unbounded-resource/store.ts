// The helpers a handler reaches, and the containers they install into.
//
// Both containers are declared here, beside the write, because that is the only place a
// write's destination has an identity: an imported binding is not a value in this IR and
// a write into one records no destination at all. Stated rather than worked around --
// the claim in the coverage ledger names it as a miss.
const calculators: Record<string, { widgetId: string }> = {};
const sessions: Record<string, { widgetId: string }> = {};

const knownWidgets: Record<string, { name: string }> = { alpha: { name: "Alpha" } };

// A lookup. It answers whether an identifier names a widget that exists, which is the
// answer that bounds a container keyed by it: the number of widgets is not the caller's
// to choose.
export async function findWidget(id: string): Promise<{ name: string } | undefined> {
  return knownWidgets[id];
}

// A per-widget calculator, installed the first time anybody asks for one. The write is
// here and the decision about whether to make it is in whatever called this, which is
// exactly why the judgement cannot stop at the function boundary.
export function calculatorFor(widgetId: string): { widgetId: string } {
  if (!calculators[widgetId]) {
    calculators[widgetId] = { widgetId };
  }
  return calculators[widgetId];
}

// The same installation into a different container, reached only from a handler that has
// already established the widget exists.
export function sessionFor(widgetId: string): { widgetId: string } {
  if (!sessions[widgetId]) {
    sessions[widgetId] = { widgetId };
  }
  return sessions[widgetId];
}

/** Something that costs a round trip, so a loop over it is a loop that costs something. */
export async function slowStep(id: unknown): Promise<number> {
  return String(id).length;
}

export const REGIONS = ["eu", "us", "ap"];
