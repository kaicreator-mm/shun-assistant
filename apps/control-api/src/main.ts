// CLI entry: run the local control surface on loopback.
//   node src/main.ts            → http://127.0.0.1:7788
// Env:
//   SHUN_CONTROL_PORT           — port (default 7788)
//   SHUN_CONTROL_UI_DIR         — static UI directory (default ../control-ui/public)
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DemoShunBackend } from './demo/backend.ts';
import { createControlServer } from './server.ts';

const here = dirname(fileURLToPath(import.meta.url));
const port = Number.parseInt(process.env.SHUN_CONTROL_PORT ?? '7788', 10);
const uiDir = process.env.SHUN_CONTROL_UI_DIR ?? resolve(here, '../../control-ui/public');

const backend = new DemoShunBackend();
const handle = createControlServer({ backend, uiDir, port });
const bound = await handle.start();
console.log(`Shun control surface (T08 demo backend) on http://127.0.0.1:${bound}`);
console.log('Local only: the surface refuses non-loopback binds and non-loopback Host headers.');
