// A class that uses parameter decorators this engine recognizes, on methods whose
// ROUTING decorators it does not.
//
// This fixture used `@RestController`, which the engine now recognizes -- any class
// decorator whose name ends in Controller is one, because `@Controller`, `@RestController`
// and `@JsonController` are three names for one declaration. `@Resource` is not, and the
// point of the fixture is the case that is still unmapped rather than any particular
// framework.
//
// Frameworks borrow each other's parameter vocabulary. `@Body()` means the same thing
// in several of them, but a routing decorator this engine has no model for means the
// method was never enumerated as an entry point. Input is identified; the route around
// it is not. Everything found here is a real flow and none of it is an assertion about
// an attack surface this engine mapped.
import { Body, Param } from "./framework.ts";
import { execSync } from "node:child_process";

declare function Resource(path: string): ClassDecorator;
declare function Delete(path: string): MethodDecorator;

@Resource("/tags")
export class TagsController {
  @Delete("/:id")
  async deleteTag(@Param("id") id: string, @Body() body: { reason: string }) {
    execSync(`tag-tool remove ${id} --reason ${body.reason}`);
  }
}
