export default async function AccountPage(props: {
  params: Promise<{ accountId: string }>;
}) {
  const params = await props.params;
  return params.accountId;
}
