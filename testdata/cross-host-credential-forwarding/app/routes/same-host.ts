/** Same-host forwarding retains the request's authority and is not a finding. */
export async function loader({ request }: { request: Request }) {
  const target = new URL("https://app.example/ingest");
  const headers = new Headers(request.headers);

  return fetch(target, { headers });
}
