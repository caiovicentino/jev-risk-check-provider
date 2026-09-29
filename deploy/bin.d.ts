// Wrangler bundles *.bin files as Data modules (ArrayBuffer); see [[rules]] in wrangler.toml.
declare module "*.bin" {
  const data: ArrayBuffer;
  export default data;
}
