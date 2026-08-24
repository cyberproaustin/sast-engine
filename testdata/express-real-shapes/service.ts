import { exec } from "child_process";

export function lookup(target: string): string {
  const cmd = `nslookup ${target}`;
  exec(cmd);
  return cmd;
}
