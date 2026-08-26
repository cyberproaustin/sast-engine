// Not under `pages`, and imported by the handlers: the data layer a route calls into.

export async function listLinks(collection: unknown) {
  return [{ id: 1, collection }];
}

export async function createLink(input: unknown) {
  return { id: 2, input };
}

export async function getLink(id: number) {
  return { id };
}

export async function updateLink(id: number, input: unknown) {
  return { id, input };
}

export async function removeLink(id: number) {
  return { id };
}
