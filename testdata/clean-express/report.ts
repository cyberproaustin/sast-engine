// Ordinary helpers that pass untrusted data around without ever executing it.
// A tool that flags "user input reaches a function" rather than "user input
// reaches a dangerous operation" will produce noise here.

export function buildReport(note: string): string {
  return `note: ${note.trim()}`;
}

export function renderStatus(message: string): string {
  return message.toUpperCase();
}
