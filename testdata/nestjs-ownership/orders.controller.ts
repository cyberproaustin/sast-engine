import { Controller, Delete, Get, Param } from "@nestjs/common";
import { AuthWorkspace, UserSession, UserAgent } from "./session.ts";

declare const prisma: {
  order: {
    delete(a: unknown): Promise<void>;
    findUnique(a: unknown): Promise<{ id: string }>;
    update(a: unknown): Promise<void>;
  };
};

@Controller("orders")
export class OrdersController {
  // Scoped by the caller's identity as part of the selection. No comparison appears
  // anywhere, and none is needed: this cannot reach another tenant's record.
  @Delete(":id")
  async remove(@Param("id") id: string, @UserSession() user: { id: string }) {
    await prisma.order.delete({ where: { id, userId: user.id } });
  }

  // Identity is injected and then ignored. The caller alone chooses the record.
  @Get(":id")
  async read(@Param("id") id: string, @UserSession() user: { id: string }) {
    return prisma.order.findUnique({ where: { id } });
  }

  // A decorator that only looks like identity must not scope anything.
  //
  // Identity IS injected here, so the judgement is made rather than set aside; what is
  // under test is purely whether @UserAgent scopes the selection. It must not: it reads a
  // header, which the caller chooses. Written this way because the earlier version had no
  // identity parameter at all, which meant a model that wrongly treated UserAgent as
  // identity and a model that correctly refused to judge produced the same silence.
  @Get(":id/trace")
  async trace(
    @Param("id") id: string,
    @UserSession() user: { id: string },
    @UserAgent() agent: string,
  ) {
    return prisma.order.findUnique({ where: { id, agent } });
  }

  // Scoped by a SEPARATE argument rather than inside the selector. The same statement
  // made with two arguments instead of one nested object: the operation was handed the
  // caller's identity and cannot reach a record they do not own.
  @Delete(":id/attachments")
  async removeAttachment(
    @Param("id") id: string,
    @UserSession() user: { id: string },
  ) {
    await store.delete(id, user.id);
  }

  // Scoped by the tenant the request was authenticated into.
  @Delete(":id/exports")
  async removeExport(
    @Param("id") id: string,
    @AuthWorkspace() workspace: { id: string },
  ) {
    await store.delete(id, workspace.id);
  }

  // Handed no identity at all, in an application that injects identity everywhere else.
  // This is what a login flow, an OAuth callback and an invite redemption look like, and
  // the policy has nothing to compare against. Reported, not counted, never gating: 42
  // findings of this shape were adjudicated against sixteen production repositories and
  // the precision was 0.00.
  @Get("public/:id")
  async readPublic(@Param("id") id: string) {
    return prisma.order.findUnique({ where: { id } });
  }
}

declare const store: { delete(id: string, owner: string): Promise<void> };
