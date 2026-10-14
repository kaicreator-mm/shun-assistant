// events.mjs — immediate-append NDJSON event stream for the i86-U04 pilot.
// Every step of every leg appends one line the moment it happens; the run
// must remain reconstructable even if a later step crashes the process.
import { appendFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

export class Events {
  #path;
  #leg;
  #console;

  constructor(path, leg) {
    this.#path = path;
    this.#leg = leg;
    this.#console = process.env.EVENTS_QUIET ? false : true;
  }

  async emit(type, detail, extra = {}) {
    const rest = typeof extra === 'string' ? { note: extra } : extra;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      leg: this.#leg,
      type,
      detail: typeof detail === 'string' ? detail : JSON.stringify(detail),
      ...rest,
    });
    await mkdir(dirname(this.#path), { recursive: true });
    await appendFile(this.#path, line + '\n', 'utf8');
    if (this.#console) console.log(`[${this.#leg}] ${type} :: ${line.slice(0, 400)}`);
  }

  async emitRaw(record) {
    const line = JSON.stringify({ ts: new Date().toISOString(), leg: this.#leg, ...record });
    await mkdir(dirname(this.#path), { recursive: true });
    await appendFile(this.#path, line + '\n', 'utf8');
    if (this.#console) console.log(`[${this.#leg}] ${line.slice(0, 400)}`);
  }
}
