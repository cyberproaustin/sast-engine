// A handler given an input this scan cannot read.
//
// `UserSession` is defined in a sibling workspace package, which is outside the tree
// being scanned — the shape every monorepo produces when the scan is rooted at one
// service. The engine sees a parameter decorator it has never met, and it cannot know
// whether that parameter carries the caller's identity or a request header.
//
// It must not conclude that the handler never consulted who the caller is. That
// conclusion would be about an input nobody read. Saying which decorator it was, and
// that the definition is not in the tree, turns a wrong answer into a fixable one.
import { Controller, Delete, Param } from "@nestjs/common";
import { UserSession } from "@acme/platform-auth";

declare const prisma: { order: { delete(a: unknown): Promise<void> } };

@Controller("orders")
export class OrdersController {
  @Delete(":id")
  async remove(@Param("id") id: string, @UserSession() user: { id: string }) {
    await prisma.order.delete({ where: { id } });
  }
}
