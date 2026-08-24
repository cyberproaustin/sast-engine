export async function loadOrder(id: string): Promise<{ id: string }> {
  if (!id) throw new Error("driver: relation \"orders\" does not exist");
  return { id };
}

// Something that is not an HTTP response but exposes a method of the same name.
export const auditSink = {
  json(payload: unknown): void {
    void payload;
  },
};
