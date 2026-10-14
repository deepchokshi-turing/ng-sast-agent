const assert = require("assert");
const { handle } = require("../src/agent");

assert.strictEqual(handle("what is two plus two"), "4");
console.log("ok");
