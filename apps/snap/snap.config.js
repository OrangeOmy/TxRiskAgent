/** @type {import('@metamask/snaps-cli').SnapConfig} */
const config = {
  input: 'src/index.ts',
  output: {
    path: 'dist',
    filename: 'bundle.js',
    clean: true,
  },
  server: {
    enabled: true,
    root: '.',
    port: 8080,
  },
};

export default config;
