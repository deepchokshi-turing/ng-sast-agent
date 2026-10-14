// Stub model client. A real deployment calls a hosted model here.
function complete(prompt) {
  return { expression: "2 + 2" };
}

module.exports = { complete };
