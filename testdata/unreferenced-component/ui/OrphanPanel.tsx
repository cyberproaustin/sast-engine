// The shape this corpus exists for. A component-local handler was enough to have this
// reported at error level as though it stood on the enumerated surface, and the
// component is not imported, re-exported or dynamically loaded anywhere in the tree.
// The finding is not withdrawn -- the code says what it says -- but the claim about
// where it is, is.
export function OrphanPanel() {
  const openSettings = () => {
    window.open("https://settings.example.com", "_blank");
  };
  return { openSettings };
}
