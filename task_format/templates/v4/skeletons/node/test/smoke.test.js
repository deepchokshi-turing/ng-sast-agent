'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { handle } = require('../src/index.js');

test('runs', () => {
  assert.ok(handle('hello').answer);
});
