// fix-string-undefined.ts
import { Project, SyntaxKind } from "ts-morph";
import path from "path";

const project = new Project({
  tsConfigFilePath: path.join(process.cwd(), "tsconfig.json"),
});

project.getSourceFiles("src/**/*.{ts,tsx}").forEach((file) => {
  let changed = false;

  // 1. useState<string>() → useState<string>("")
  file.getDescendantsOfKind(SyntaxKind.CallExpression).forEach((call) => {
    const expr = call.getExpression().getText();
    if (expr.includes("useState") && call.getArguments().length === 0) {
      const typeArg = call.getTypeArguments()[0]?.getText();
      if (typeArg === "string") {
        call.addArgument('""');
        changed = true;
      }
    }
  });

  // 2. string | undefined → ?? ""
  file.getDescendantsOfKind(SyntaxKind.VariableDeclaration).forEach((decl) => {
    const typeNode = decl.getTypeNode();
    if (typeNode && typeNode.getText().includes("string | undefined")) {
      const init = decl.getInitializer();
      if (init && !init.getText().includes("??")) {
        decl.setInitializer(`(${init.getText()} ?? "")`);
        changed = true;
      }
    }
  });

  if (changed) {
    console.log(`✅ Düzenlendi: ${file.getFilePath()}`);
  }
});

project.saveSync();
