export default {
  rootDir: process.cwd(),
  moduleFileExtensions: ["ts", "tsx", "js"],
  transform: {
    "^.+\\.tsx?$": [
      "esbuild-jest",
      {
        sourcemap: true,
        loaders: {
          ".spec.ts": "tsx",
        },
      },
    ],
  },
  testPathIgnorePatterns: ["/node_modules/", "/.generator/"],
};
