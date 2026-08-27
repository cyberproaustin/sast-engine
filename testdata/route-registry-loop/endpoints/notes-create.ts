// One endpoint module of the registry. The name the URL is served at is the name this
// module is re-exported under, not anything written inside it.
export const meta = { requireCredential: true };

export default async function exec(params: { text: string }): Promise<string> {
  return params.text;
}
