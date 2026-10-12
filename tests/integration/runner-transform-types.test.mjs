import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ParameterPropertyProbe } from './runner-fixture-parameter-property.ts';

test('integration runner loads production-style TypeScript parameter properties', () => {
  assert.equal(new ParameterPropertyProbe('ok').value, 'ok');
});
