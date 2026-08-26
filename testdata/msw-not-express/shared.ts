// A local re-export, which is how a story file ends up registering handlers under a name
// that has no import from `msw` anywhere in it.
export const rest = {
  post(path: string, handler: unknown) {
    return { path, handler };
  },
  get(path: string, handler: unknown) {
    return { path, handler };
  },
};
