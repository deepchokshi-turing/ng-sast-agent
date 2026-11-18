// Build check, offline and without dependencies: syntax-check every JavaScript and TypeScript
// source under the directories (or files) given as arguments, default `src`. `node --check` does
// not strip types, so each .ts/.mts/.cts file is first type-stripped with node:module's
// stripTypeScriptTypes (what Node 24 does when it runs the file) and the result is checked.
// Usage: node scripts/check-syntax.mjs [dir-or-file ...]
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { extname, join } from "node:path";

const SKIP = new Set(["node_modules", "dist", "build", ".git"]);
const TS = { ".ts": "module", ".mts": "module", ".cts": "commonjs" };
const JS = new Set([".js", ".mjs", ".cjs"]);

function wanted(file) {
	const ext = extname(file);
	return JS.has(ext) || (ext in TS && !/\.d\.[mc]?ts$/.test(file));
}

function walk(path) {
	if (!statSync(path).isDirectory()) return wanted(path) ? [path] : [];
	return readdirSync(path, { withFileTypes: true }).flatMap((entry) =>
		entry.isDirectory() && SKIP.has(entry.name) ? [] : walk(join(path, entry.name)),
	);
}

const roots = process.argv.slice(2).length ? process.argv.slice(2) : ["src"];
const missing = roots.filter((root) => !existsSync(root));
const files = roots.filter((root) => existsSync(root)).flatMap(walk);
let failed = missing.length;
for (const root of missing) console.error(`${root}: not found`);
for (const file of files) {
	try {
		const type = TS[extname(file)];
		if (type) {
			const js = stripTypeScriptTypes(readFileSync(file, "utf-8"));
			execFileSync(process.execPath, [`--input-type=${type}`, "--check"], { input: js, stdio: ["pipe", "ignore", "pipe"] });
		} else {
			execFileSync(process.execPath, ["--check", file], { stdio: ["ignore", "ignore", "pipe"] });
		}
	} catch (error) {
		failed += 1;
		const detail = error?.stderr?.length ? String(error.stderr).trim() : error instanceof Error ? error.message : String(error);
		console.error(`${file}: ${detail}`);
	}
}
if (!files.length && !missing.length) {
	console.error(`no .js/.mjs/.cjs/.ts/.mts/.cts files under ${roots.join(", ")}`);
	failed = 1;
}
console.log(failed ? `${failed} problem(s) in ${files.length} file(s)` : `syntax ok (${files.length} files)`);
process.exit(failed ? 1 : 0);
