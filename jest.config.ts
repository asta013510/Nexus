import type { Config } from 'jest';

const config: Config = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/packages', '<rootDir>/apps'],
  testMatch: ['**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest',
      {
        tsconfig: {
          target: 'ES2022',
          module: 'commonjs',
          lib: ['ES2022', 'DOM'],
          strict: true,
          esModuleInterop: true,
          skipLibCheck: true,
          forceConsistentCasingInFileNames: true,
          resolveJsonModule: true,
          declaration: true,
          declarationMap: true,
          sourceMap: true,
          outDir: './dist',
          rootDir: '.',
          composite: true,
          exactOptionalPropertyTypes: false, // Disable for tests
          noUncheckedIndexedAccess: false, // Disable for tests
        },
      },
    ],
  },
  moduleNameMapper: {
    '^@zero/shared$': '<rootDir>/packages/shared/src/index.ts',
    '^@zero/crypto$': '<rootDir>/packages/crypto/src/index.ts',
    '^@zero/database$': '<rootDir>/packages/database/src/index.ts',
    '^@zero/security$': '<rootDir>/packages/security/src/index.ts',
    '^@zero/auth$': '<rootDir>/packages/auth/src/index.ts',
  },
  collectCoverageFrom: [
    'packages/**/*.ts',
    '!packages/**/dist/**',
    '!packages/**/*.d.ts',
    '!packages/**/*.test.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  coverageThreshold: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],
  testTimeout: 30000,
  verbose: true,
  silent: false,
  forceExit: true,
  detectOpenHandles: true,
};

export default config;
