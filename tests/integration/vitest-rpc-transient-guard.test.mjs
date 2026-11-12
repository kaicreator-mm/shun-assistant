import test from 'node:test';
import assert from 'node:assert/strict';
import { isVitestWorkerRpcTransient } from './vitest-rpc-transient-guard.mjs';

const suite = { requiresVitest: true };
const marker = 'Error: [vitest-worker]: Timeout calling "onTaskUpdate"';
const green = ' Test Files  1 passed (1)\n Tests  24 passed | 3 skipped (27)\n';
const result = (text, extras = {}) => ({
  stdout: Buffer.from(text), stderr: Buffer.alloc(0), status: 1,
  signal: null, error: null, ...extras,
});

test('only retries a worker-RPC timeout after explicit all-green test summaries', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + marker)), true);
});
test('mixed real test failure plus RPC timeout never retries', () => {
  const output = ' Test Files  1 failed | 1 passed (2)\n Tests  1 failed | 24 passed (25)\n' + marker;
  assert.equal(isVitestWorkerRpcTransient(suite, result(output)), false);
});
test('does not retry a normal failed test with no worker timeout marker', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(' Test Files  1 failed (1)\n Tests  1 failed (1)')), false);
});
test('does not retry a timeout with no reliable test summary', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(marker)), false);
});
test('does not retry a timeout that shares output with another failed count', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + ' 2 failed\n' + marker)), false);
});
test('does not retry on spawn error or signal termination', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + marker, { error: new Error('spawn failed') })), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + marker, { status: null, signal: 'SIGKILL' })), false);
});
test('does not retry non-Vitest or zero-exit suites', () => {
  assert.equal(isVitestWorkerRpcTransient({ requiresVitest: false }, result(green + marker)), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + marker, { status: 0 })), false);
});
test('understands ANSI-colored Vitest green summaries', () => {
  const color = '\x1b[32m' + green + '\x1b[0m' + marker;
  assert.equal(isVitestWorkerRpcTransient(suite, result(color)), true);
});
