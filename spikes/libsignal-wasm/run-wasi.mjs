// Runs the wasm32-wasip1 round-trip binary under Node's built-in WASI —
// proves libsignal-protocol (PQXDH + Triple Ratchet + SPQR) *executes* correctly
// in a WebAssembly sandbox, no native code anywhere.
import { readFile } from "node:fs/promises";
import { WASI } from "node:wasi";

const wasi = new WASI({ version: "preview1", args: ["roundtrip"] });
const wasm = await WebAssembly.compile(
  await readFile(new URL("./target/wasm32-wasip1/release/roundtrip.wasm", import.meta.url)),
);
const instance = await WebAssembly.instantiate(wasm, wasi.getImportObject());
const start = performance.now();
const code = wasi.start(instance);
console.log(`      wasm run: exit=${code}, ${(performance.now() - start).toFixed(0)}ms under Node ${process.version} WASI`);
process.exit(code);
