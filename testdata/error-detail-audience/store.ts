// A driver error: schema names, query text, connection detail. This is what makes a
// caught error worth withholding from whoever asked.
export async function loadReport(id: string, owner: number): Promise<{ id: string }> {
  if (!id) {
    throw new Error(`driver: relation "reports" does not exist (owner=${owner})`);
  }
  return { id };
}
