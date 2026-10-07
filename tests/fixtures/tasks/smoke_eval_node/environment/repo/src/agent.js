// Calculator assistant: the model writes an arithmetic expression, a tool evaluates it.
const { complete } = require("./llm");

// Tool: evaluate the expression the model wrote.
function calculate(expression) {
  return String(eval(expression));
}

function handle(question) {
  const reply = complete(`Write one JavaScript arithmetic expression that answers: ${question}`);
  return calculate(reply.expression);
}

module.exports = { calculate, handle };
