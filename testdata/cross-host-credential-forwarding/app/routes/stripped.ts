/** A cross-host proxy that deliberately removes both ambient credential headers. */
export async function loader({ request }: { request: Request }) {
  const target = new URL("https://app.example/ingest");
  target.hostname = "telemetry.example";
  const headers = new Headers(request.headers);
  headers.delete("Cookie");
  headers.delete("Authorization");

  return fetch(target, { headers });
}
