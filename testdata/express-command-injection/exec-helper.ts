import { exec } from "child_process";

// The sink lives in a different module from the entry point on purpose: a
// single-function or single-file analysis cannot connect these.
export function runPing(host: string): string {
  const cmd = `ping -c 1 ${host}`;
  exec(cmd);
  return cmd;
}

export function runLookup(domain: string): string {
  exec("nslookup " + domain);
  return domain;
}
