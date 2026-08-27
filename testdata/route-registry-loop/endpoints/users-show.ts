export const meta = { requireCredential: false };

export default async function exec(params: { userId: string }): Promise<string> {
  return params.userId;
}
