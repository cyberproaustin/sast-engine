// The authorization service, in the shape production code writes it: it is handed the
// caller, a named permission, and the SCOPE the permission is being asked about.
//
// That third argument is the whole subject of this corpus. A rule that only asks whether
// a call carrying the caller's identity happened cannot see it, and answers "checked" for
// every handler here -- including the ones that go on to write somewhere else.
export const UPDATE_STRATEGY = "UPDATE_STRATEGY";
export const DELETE_PROJECT = "DELETE_PROJECT";
export const DELETE_LINK = "DELETE_LINK";
export const UPDATE_SEGMENT = "UPDATE_SEGMENT";

export const access = {
  async hasPermission(user: unknown, permission: string, scope: string): Promise<boolean> {
    return Boolean(user) && scope !== "";
  },
  // A permission with no scope at all. An administrator acting on any record is what
  // this endpoint is FOR, so there is no second key for the check to have named.
  async hasRole(user: unknown, role: string): Promise<boolean> {
    return Boolean(user) && role !== "";
  },
};
