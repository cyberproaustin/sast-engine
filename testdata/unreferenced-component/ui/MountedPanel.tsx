// Rendered: the page above imports it. Same call as the orphan beside it, and the
// difference between them is the whole judgement.
export function MountedPanel() {
  const openHelp = () => {
    window.open("https://help.example.com", "_blank");
  };
  return { openHelp };
}
