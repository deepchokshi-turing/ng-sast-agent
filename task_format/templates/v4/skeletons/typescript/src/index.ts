// Node 24 runs this file directly (type stripping): use erasable TypeScript only (no enums,
// namespaces or parameter properties) and explicit .ts extensions in relative imports.
import { pathToFileURL } from "node:url";

export interface Answer {
  answer: string;
}

export function handle(request: string): Answer {
  return { answer: `TODO: handle ${JSON.stringify(request)}` };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const request: string = process.argv.slice(2).join(' ') || 'hello';
  console.log(JSON.stringify(handle(request), null, 2));
}
