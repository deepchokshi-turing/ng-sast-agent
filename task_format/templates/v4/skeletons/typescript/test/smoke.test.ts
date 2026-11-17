import test from 'node:test';
import assert from 'node:assert';
import { handle } from '../src/index.ts';

test('runs', () => {
  assert.ok(handle('hello').answer);
});
