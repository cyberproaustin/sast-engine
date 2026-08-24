// NestJS registers routes by decorating class methods, and injects request data
// straight into parameters. None of the Express detection applies, and the parameter
// itself is the source — there is no request object to take a property of.

import { Controller, Get, Delete, Param, Query, UseGuards } from "@nestjs/common";
import { exec } from "child_process";

@Controller("orders")
@UseGuards(AuthGuard)
export class OrdersController {
  // EXPECTED FINDING — @Param data reaching a shell.
  @Get(":id/trace")
  trace(@Param("id") id: string) {
    exec(`traceroute ${id}`);
    return id;
  }

  // EXPECTED FINDING — @Query is equally caller-supplied.
  @Get("search")
  search(@Query("q") q: string) {
    exec(`grep ${q} /var/log/orders`);
    return q;
  }

  // EXPECTED CLEAN — no caller-supplied data reaches the command.
  @Get("health")
  health() {
    exec("uptime");
    return "ok";
  }

  // EXPECTED CLEAN for dataflow; carries an extra route-level guard, which the
  // surface must distinguish from the class-level one.
  @Delete(":id")
  @UseGuards(AdminGuard)
  remove(@Param("id") id: string) {
    return id;
  }
}
