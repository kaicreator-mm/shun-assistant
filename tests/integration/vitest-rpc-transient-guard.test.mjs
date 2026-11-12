import test from 'node:test';
import assert from 'node:assert/strict';
import { isVitestWorkerRpcTransient } from './vitest-rpc-transient-guard.mjs';

const suite = { requiresVitest: true };
const marker = 'Error: [vitest-worker]: Timeout calling "onTaskUpdate"';
const green = ' Test Files  1 passed (1)\n Tests  24 passed | 3 skipped (27)\n';
const one = 'Vitest caught 1 unhandled error during the test run.\n';
const result = (text, extras = {}) => ({
  stdout: Buffer.from(text), stderr: Buffer.alloc(0), status: 1,
  signal: null, error: null, ...extras,
});

test('only retries a single counted worker-RPC error with all-green summaries', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker)), true);
});
test('mixed failed tests and RPC never retry', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(' Test Files  1 failed | 1 passed (2)\n Tests  1 failed | 24 passed (25)\n' + one + marker)), false);
});
test('normal failed test never retries', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(' Tests  1 failed (1)')), false);
});
test('missing test summaries never retry', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(one + marker)), false);
});
test('unknown failed counts never retry', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + '2 failed\n' + one + marker)), false);
});
test('spawn error or signal never retries', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker, { error: new Error('spawn failed') })), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker, { status: null, signal: 'SIGKILL' })), false);
});
test('non-Vitest or clean exit never retries', () => {
  assert.equal(isVitestWorkerRpcTransient({ requiresVitest: false }, result(green + one + marker)), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker, { status: 0 })), false);
});
test('ANSI-colored all-green summary and single RPC error qualifies', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result('\x1b[32m' + green + '\x1b[0m' + one + marker)), true);
});
test('genuine TypeError accompanying RPC must fail closed despite green tests', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + 'Vitest caught 2 unhandled errors during the test run.\n' + marker + '\nTypeError: Cannot read currentness')), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker + '\nTypeError: Cannot read currentness')), false);
});
test('second independent generic Error accompanying RPC must fail closed', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker + '\nError: AUTHORITY_INVARIANT_BROKEN')), false);
});
test('duplicate known RPC headers or error section fails closed', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + marker + '\n' + marker)), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + 'Unhandled Error\n' + marker + '\nUnhandled Error')), false);
});
test('ambiguous or truncated unhandled error count never retries', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + marker)), false);
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + 'Vitest caught 2 unhandled errors during the test run.\n' + marker)), false);
});
test('wrong or unknown RPC method is not considered a known transient', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + one + 'Error: [vitest-worker]: Timeout calling "onUnknownMethod"')), false);
});
test('summary with another embedded test failure is not retried', () => {
  assert.equal(isVitestWorkerRpcTransient(suite, result(green + 'Tests 1 failed\n' + one + marker)), false);
});
