import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "coverage/**", "reports/**", ".worktrees/**"] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: { allowDefaultProject: ["vitest.config.ts"] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-confusing-void-expression": "off",
    },
  },

  {
    files: ["**/test/**/*.ts", "tests/**/*.ts"],
    ...tseslint.configs.disableTypeChecked,
  },
  {
    files: ["**/*.mjs", "eslint.config.js"],
    ...tseslint.configs.disableTypeChecked,
  },
);
