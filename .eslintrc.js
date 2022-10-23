module.exports = {
  env: {
    browser: true,
    node: true,
    es2021: true,
  },
  root: true,
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended", "plugin:prettier/recommended"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 12,
    sourceType: "module",
    project: ["./tsconfig.json"],
  },
  ignorePatterns: ["**/node_modules/**", "**/dist/**", "tsconfig.json"],
  rules: {
    semi: "error",
    indent: ["error", 2, { SwitchCase: 1 }],

    // "@typescript-eslint/no-var-requires": "off",
    "@typescript-eslint/no-empty-function": "off",

    eqeqeq: ["error", "smart"],
    "@typescript-eslint/no-non-null-assertion": "error",
    "@typescript-eslint/consistent-type-assertions": [
      "error",
      {
        assertionStyle: "never",
      },
    ],

    "no-undef": "off",
  },
};
