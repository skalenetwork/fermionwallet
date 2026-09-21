// The readme's Prototype snippet must keep running against src/.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

test('readme Prototype snippet runs and pays the signed recipient', () => {
  const readme = readFileSync(fileURLToPath(new URL('../readme.md', import.meta.url)), 'utf8');
  const section = readme.slice(readme.indexOf('## Prototype'));
  const snippet = section.match(/```js\n([\s\S]*?)```/)[1];
  const src = pathToFileURL(fileURLToPath(new URL('../src/index.js', import.meta.url))).href;
  const code = snippet.replace("'./src/index.js'", JSON.stringify(src));
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', code], { encoding: 'utf8' });
  assert.match(out, /valid: true/);
  assert.match(out, /status: 'success'/);
  assert.match(out, /hmac-sha256-demo/);
});
