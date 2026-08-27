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
const seen = new Map<string,number>();
for (const sf of program.getSourceFiles()) {
  if (sf.isDeclarationFile || !files.includes(sf.fileName)) continue;
  const visit = (n: ts.Node) => {
    if (ts.isCallExpression(n) && ts.isPropertyAccessExpression(n.expression) && ["on","once","addListener"].includes(n.expression.name.text)) {
      let decls: string[] = [];
      let name = "";
      try { const t = checker.getTypeAtLocation(n.expression.expression); const s = t.getSymbol() ?? t.aliasSymbol; name = s?.getName() ?? ""; decls = (s?.getDeclarations() ?? []).map(d=>d.getSourceFile().fileName.replace(root,"")); } catch {}
      if (name) { const k = name+" <= "+decls.join(","); seen.set(k,(seen.get(k)??0)+1); }
    }
    ts.forEachChild(n, visit);
  };
  visit(sf);
}
for (const [k,v] of [...seen.entries()].sort((a,b)=>b[1]-a[1]).slice(0,15)) console.log(v, k);
