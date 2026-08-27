export const meta = { requireCredential: true };

export default async function exec(params: { noteId: string }): Promise<string> {
  return params.noteId;
}
