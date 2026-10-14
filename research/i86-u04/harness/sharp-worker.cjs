// sharp-worker.cjs — bounded worker that loads the ACQUIRED sharp binding.
//
// The binding is required DIRECTLY from the provider root (the acquired,
// hash-verified copy of @img/sharp-win32-x64). The friendly sharp API is then
// bound to that exact binding via a Module._load hook, so every pixel of the
// resize runs through the acquired native bytes. Plain CJS on purpose: runs
// unmodified under Node 22 and Node 24.
//
// argv: <mode run|crash> <providerRoot> <resultJsonPath> <inputPngPath> <outputPngPath>
const fs = require('fs');
const path = require('path');

const [mode, providerRoot, resultPath, inputPngPath, outputPngPath] = process.argv.slice(2);
const result = {
  mode,
  providerRoot,
  node: process.version,
  abi: Number(process.versions.modules),
  napi: Number(process.versions.napi),
  platform: process.platform,
  arch: process.arch,
  execPath: process.execPath,
};
try {
  const bindingPath = path.join(providerRoot, 'index.cjs');
  const binding = require(bindingPath);
  result.bindingLoadedFrom = bindingPath;
  const libvipsInfo = binding.libvipsVersion();
  result.libvipsVersion = typeof libvipsInfo === 'string' ? libvipsInfo : JSON.stringify(libvipsInfo);
  result.bindingFormats = Object.keys(binding.format ? binding.format() : {}).slice(0, 4);

  // Bind the friendly API to the ACQUIRED binding (hostile-variant catalogs
  // never reach this worker; this hook is the point where acquired bytes, not
  // pnpm-store bytes, execute).
  const Module = require('module');
  const origLoad = Module._load;
  let hookedUses = 0;
  Module._load = function (request) {
    // sharp's dist does: require("@img/sharp-win32-x64/sharp.node")
    if (request === '@img/sharp-win32-x64/sharp.node' || request === '@img/sharp-win32-x64') {
      hookedUses += 1;
      return binding;
    }
    return origLoad.apply(this, arguments);
  };
  const { createRequire } = require('module');
  const requireFromImage = createRequire('C:\\xDev\\kAiCreator\\shun-assistant\\i86-u04-zc\\packages\\vertical-image\\package.json');
  const sharp = requireFromImage('sharp');
  result.sharpApiVersion = sharp.versions?.sharp ?? null;
  result.apiBindsAcquiredBinding = null; // set after first hook use

  if (mode === 'crash') {
    // crash AFTER the acquired native binding loaded: parent must survive and
    // recover; no locks exist to clean (libvips keeps no file locks).
    result.crashAfterLoad = true;
    fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
    process.exit(1);
  }

  const input = fs.readFileSync(inputPngPath);
  sharp(input)
    .resize(20, 10, { fit: 'fill' })
    .png()
    .toBuffer()
    .then((out) => {
      fs.writeFileSync(outputPngPath, out);
      result.hookedUses = hookedUses;
      result.apiBindsAcquiredBinding = hookedUses > 0;
      result.outputBytes = out.length;
      fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
      process.exit(0);
    })
    .catch((error) => {
      result.error = String(error).slice(0, 300);
      fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
      process.exit(2);
    });
} catch (error) {
  result.fatal = String((error && error.stack) || error).slice(0, 500);
  fs.writeFileSync(resultPath, JSON.stringify(result, null, 2));
  process.exit(3);
}
