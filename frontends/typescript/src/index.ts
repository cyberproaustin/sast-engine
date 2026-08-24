// CLI: lower a TypeScript/JavaScript source tree into Program IR on stdout.
//
//   node src/index.ts <rootDir> [--out <file>]
//
// The frontend emits IR and exits. It never reports a finding — that is the core's
// job, and the separation is the point (ADR-001).

import fs from "node:fs";
import path from "node:path";

import { lowerProgram, relativizeLocations } from "./lower.ts";
import type { IRDoc } from "./ir.ts";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"]);
const SKIP_DIRECTORIES = new Set(["node_modules", ".git", "dist", "build", "out", "coverage"]);

function collectSources(rootDir: string): string[] {
  const found: string[] = [];

  const walk = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) continue;
        walk(full);
        continue;
      }
      if (entry.name.endsWith(".d.ts")) continue;
      if (SOURCE_EXTENSIONS.has(path.extname(entry.name))) found.push(full);
    }
  };

  walk(rootDir);
  return found.sort();
}

/**
 * Serializes the IR one array element at a time.
 *
 * A single JSON.stringify of the whole document fails outright on a large program:
 * V8 caps string length, and a monorepo server produced an IR past that cap, so the
 * frontend reported "Invalid string length" and lowered nothing. Nothing about the
 * analysis was wrong — the result simply could not be handed across the seam. Peak
 * memory here is one function, not one program.
 */
function writeIR(fd: number, doc: IRDoc): void {
  const w = (s: string): void => {
    fs.writeSync(fd, s);
  };
  const array = <T>(name: string, items: T[], last: boolean): void => {
    w(`  "${name}": [`);
    items.forEach((item, i) => {
      w(`${i === 0 ? "\n" : ",\n"}    ${JSON.stringify(item)}`);
    });
    w(`${items.length ? "\n  " : ""}]${last ? "" : ","}\n`);
  };

  w("{\n");
  w(`  "irVersion": ${JSON.stringify(doc.irVersion)},\n`);
  w(`  "frontend": ${JSON.stringify(doc.frontend)},\n`);
  array("modules", doc.modules, false);
  array("functions", doc.functions, false);
  array("entryPoints", doc.entryPoints, true);
  w("}\n");
}

function main(): number {
  const argv = process.argv.slice(2);
  const rootArg = argv.find((a) => !a.startsWith("--"));
  if (!rootArg) {
    process.stderr.write("usage: node src/index.ts <rootDir> [--out <file>]\n");
    return 2;
  }

  const rootDir = path.resolve(rootArg);
  if (!fs.existsSync(rootDir) || !fs.statSync(rootDir).isDirectory()) {
    process.stderr.write(`not a directory: ${rootDir}\n`);
    return 2;
  }

  const files = collectSources(rootDir);
  if (files.length === 0) {
    process.stderr.write(`no source files under ${rootDir}\n`);
    return 2;
  }

  try {
    const doc = relativizeLocations(lowerProgram({ rootDir, files }), rootDir);

    const outIndex = argv.indexOf("--out");
    const outPath = outIndex !== -1 ? argv[outIndex + 1] : undefined;
    const fd = outPath ? fs.openSync(outPath, "w") : 1;
    try {
      writeIR(fd, doc);
    } finally {
      if (outPath) fs.closeSync(fd);
    }

    if (outPath) {
      process.stderr.write(
        `lowered ${doc.functions.length} function(s), ${doc.entryPoints.length} entry point(s) -> ${outPath}\n`,
      );
    }
    return 0;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`lowering failed: ${message}\n`);
    return 1;
  }
}

process.exit(main());
