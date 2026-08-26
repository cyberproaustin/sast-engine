// Mock Service Worker. `http.post("/api/drive/files", handler)` is the same four tokens
// as an Express route registration and means the opposite: this handler answers a fetch
// the browser makes to ITSELF while a component story runs. Nothing here is served to
// anybody, and the receiver is called `http`, so no type resolution was ever going to
// tell it apart from a router.
//
// The import is the whole of the evidence.
import { http, HttpResponse } from "msw";

export const commonHandlers = [
  http.post("/api/drive/files", async ({ request }) => {
    const body = await request.json();
    return HttpResponse.json({ id: "1", name: body.name });
  }),
  http.get("/api/charts/notes", ({ request }) => {
    return HttpResponse.json({ url: request.url });
  }),
];
