// A page. Nothing imports it and nothing was ever going to: the framework loads it by
// PATH, and treating "no import" as "no caller" here would be a statement about the
// framework rather than about the program.
import { MountedPanel } from "../ui/MountedPanel.tsx";

export default function Dashboard() {
  const openDocs = () => {
    window.open("https://docs.example.com", "_blank");
  };
  return { openDocs, MountedPanel };
}
