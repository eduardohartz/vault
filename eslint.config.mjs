import antfu from "@antfu/eslint-config"
import nextPlugin from "@next/eslint-plugin-next"
import jestDom from "eslint-plugin-jest-dom"
import jsxA11y from "eslint-plugin-jsx-a11y"

export default antfu(
  {
    react: true,
    typescript: true,

    lessOpinionated: true,
    isInEditor: false,

    stylistic: {
      semi: false,
      indent: 2,
      quotes: "double",
    },

    formatters: {
      css: true,
    },

    ignores: ["migrations/**/*", "next-env.d.ts", "eslint.config.mjs"],
  },
  jsxA11y.flatConfigs.recommended,
  {
    plugins: {
      "@next/next": nextPlugin,
    },
    rules: {
      ...nextPlugin.configs.recommended.rules,
      ...nextPlugin.configs["core-web-vitals"].rules,
    },
  },
  {
    files: ["**/*.test.ts?(x)"],
    ...jestDom.configs["flat/recommended"],
  },
  {
    files: ["**/*.spec.ts", "**/*.e2e.ts"],
  },
  {
    rules: {
      "style/brace-style": ["error", "1tbs"],
      "@typescript-eslint/consistent-type-definitions": ["error", "type"],
      "react/prefer-destructuring-assignment": "off",
      "node/prefer-global/process": "off",
      "react/no-array-index-key": "off",
      "react-refresh/only-export-components": "off",
      "react-hooks-extra/no-direct-set-state-in-use-effect": "off",
      "style/operator-linebreak": "off",
      "jsx-a11y/no-autofocus": "off",
      "jsx-a11y/click-events-have-key-events": "off",
      "jsx-a11y/no-static-element-interactions": "off",
      "jsx-a11y/heading-has-content": "off",
      "style/multiline-ternary": "off",
      "style/arrow-parens": "off",
    },
  },
)
