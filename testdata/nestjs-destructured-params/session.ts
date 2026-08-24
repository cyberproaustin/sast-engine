// Two custom parameter decorators. Only one of them carries the caller's identity, and
// which one is decided by what the factory reads — not by what it is called.
import { createParamDecorator } from "@nestjs/common";

export const UserSession = createParamDecorator((data: unknown, ctx: any) => {
  const req = ctx.switchToHttp().getRequest();
  return req.user;
});

// Named like identity, reads a header. A model keyed on names would get this wrong.
export const UserAgent = createParamDecorator((data: unknown, ctx: any) => {
  return ctx.switchToHttp().getRequest().headers["user-agent"];
});

// A tenant, not a user — and the application calls it a workspace. Nothing in the name
// says "identity", but the property is not part of an HTTP request, so something on the
// server put it there and the caller could not have chosen it. That is the property
// that makes a selection constrained.
export const AuthWorkspace = createParamDecorator((data: unknown, ctx: any) => {
  const request = ctx.switchToHttp().getRequest();
  return request.workspace;
});
