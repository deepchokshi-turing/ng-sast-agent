'use strict';

function handle(request) {
  return { answer: `TODO: handle ${JSON.stringify(request)}` };
}

if (require.main === module) {
  const request = process.argv.slice(2).join(' ') || 'hello';
  console.log(JSON.stringify(handle(request), null, 2));
}

module.exports = { handle };
