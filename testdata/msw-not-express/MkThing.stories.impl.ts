// The same mocks reached through a shared module, so this file imports nothing from
// `msw` at all and the import negative cannot see them. A story is a story: no
// application serves its production API out of a `*.stories.*` file.
import { rest } from "./shared.ts";

export const Default = {
  parameters: {
    msw: {
      handlers: [
        rest.post("/api/notes/create", () => ({ ok: true })),
        rest.get("/api/notes/show", () => ({ ok: true })),
      ],
    },
  },
};
