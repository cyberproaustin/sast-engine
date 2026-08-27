import ts from "typescript";
import fs from "node:fs";
import path from "node:path";
const root = process.argv[2];
const SKIP = new Set(["node_modules",".git",".yarn","dist","build","out","coverage"]);
const EXT = new Set([".ts",".tsx",".mts",".cts",".js",".jsx",".mjs",".cjs"]);
const files: string[] = [];
const walk = (d: string) => { for (const e of fs.readdirSync(d,{withFileTypes:true})) {
  const f = path.join(d,e.name);
  if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(f); continue; }
  if (e.name.endsWith(".d.ts")) continue;
  if (EXT.has(path.extname(e.name))) files.push(f);
} };
walk(root);
const program = ts.createProgram(files, {target:ts.ScriptTarget.ES2022, module:ts.ModuleKind.ESNext, moduleResolution:ts.ModuleResolutionKind.Node10, allowJs:true, noEmit:true, skipLibCheck:true, typeRoots:[path.join(root,"node_modules","@types")]});
const checker = program.getTypeChecker();
for (const sf of program.getSourceFiles()) {
  if (sf.isDeclarationFile) continue;
  if (!files.includes(sf.fileName)) continue;
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression)) {
      const m = n.expression.name.text;
      if (["on","once","addListener","addEventListener"].includes(m)) {
        let name = "";
        try { const t = checker.getTypeAtLocation(n.expression.expression); const s = t.getSymbol() ?? t.aliasSymbol; name = s ? s.getName() : checker.typeToString(t); } catch { name = "<err>"; }
        const p = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        const recv = n.expression.expression.getText(sf).replace(/\s+/g," ").slice(0,40);
        const a0 = n.arguments[0] ? n.arguments[0].getText(sf).replace(/\s+/g," ").slice(0,30) : "";
        console.log([path.relative(root, sf.fileName)+":"+(p.line+1), m, name, recv, a0, String(n.arguments.length)].join("\t"));
      }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}
