module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
     project: [
   './tsconfig.eslint.json',
    './tsconfig.build.json',
    './tsconfig.json',
    './tsconfig.tests.json',
    './tsconfig.plugins.json',
    './tsconfig.config.json'
  ],
    tsconfigRootDir: __dirname,
  },
  plugins: ['@typescript-eslint'],
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking',
    'prettier',
  ],
  rules: {
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/no-non-null-assertion': 'warn',
    'no-console': 'off',
  },
  
  env: { node: true, es2022: true },
  overrides: [
    { files: ['tests/**/*.ts'], parserOptions: { project: ['./tsconfig.tests.json'] } }
  ],
};
