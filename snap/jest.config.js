/**
 * Integration tests (test/*.test.ts) run the BUILT bundle through
 * @metamask/snaps-jest: the environment serves snap.manifest.json +
 * dist/bundle.js from this folder and executes it in MetaMask's SES execution
 * environment. Unit tests (test/unit) opt into the plain node environment.
 *
 * @type {import('jest').Config}
 */
module.exports = {
  preset: '@metamask/snaps-jest',
  testEnvironmentOptions: {
    server: { root: __dirname },
  },
  testMatch: ['<rootDir>/test/**/*.test.ts', '<rootDir>/test/**/*.test.tsx'],
  transform: {
    '^.+\\.(t|j)sx?$': [
      '@swc/jest',
      {
        jsc: {
          parser: { syntax: 'typescript', tsx: true },
          transform: { react: { runtime: 'automatic', importSource: '@metamask/snaps-sdk' } },
          target: 'es2022',
        },
        module: { type: 'commonjs' },
      },
    ],
  },
  testTimeout: 60000,
};
