export default async function SearchPage({
  searchParams,
}: {
  searchParams: { target: string };
}) {
  // The page is not an API handler, but this is still a server-side request whose
  // destination came from the page URL.
  const response = await fetch(searchParams.target);
  return response.status;
}
