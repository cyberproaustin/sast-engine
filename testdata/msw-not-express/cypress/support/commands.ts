// The end-to-end runner's own scaffolding. `cy.intercept` is spelled exactly as a
// registration -- a verb, a path and a handler -- and it stubs a request the TEST makes,
// so a surface that counts it claims the application answers at an address that exists
// only while the runner is open. Same judgement as the msw handlers beside it, reached
// through the directory rather than through an import: the runner hands `cy` to the file
// as a global, so there is nothing imported to key on.
declare const cy: {
  intercept(method: string, path: string, handler: (req: unknown) => void): void;
};

export const stubCurrentUser = (): void => {
  cy.intercept("GET", "/api/admin/user", (req) => {
    void req;
  });
};
