// A destructured parameter is still a parameter.
//
// `@AuthWorkspace() { id: workspaceId }` and `@Param() { id }` were skipped outright,
// because the lowering walked parameters and returned early for anything that was not a
// plain identifier. Both classifications were lost with them, and the loss ran in both
// directions: a query scoped by the caller's identity read as unscoped, and untrusted
// data arriving through a destructured binding was never seeded at all, so real flows
// out of it were invisible.
//
// One production codebase writes the identity form 142 times out of 462.
import { Controller, Delete, Get, Param } from "@nestjs/common";
import { AuthWorkspace, UserSession } from "./session.ts";

declare const store: {
  find(a: unknown): Promise<unknown>;
  delete(a: unknown): Promise<void>;
};

@Controller("orders")
export class OrdersController {
  // Identity arrives destructured and scopes the query. Not a finding.
  @Get(":id")
  async read(@Param("id") id: string, @AuthWorkspace() { id: workspaceId }: { id: string }) {
    return store.find({ where: { id, workspaceId } });
  }

  // Untrusted data arrives destructured and reaches a selector unscoped. A finding,
  // and one that was invisible while destructured parameters were skipped.
  @Delete()
  async remove(@Param() { id }: { id: string }, @UserSession() user: { id: string }) {
    await store.delete({ where: { id } });
  }
}
