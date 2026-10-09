// Executes frozen baseline code with the installed compiler; no old packages or network.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ts = require('typescript');
const root = '../tests/fixtures/baseline-client/';
function load(source) {
  const compiled = ts.transpileModule(source, {compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
  }}).outputText;
  const mod = {exports: {}};
  new Function('module', 'exports', compiled)(mod, mod.exports);
  return mod.exports;
}
const api = load(fs.readFileSync(root + 'api.ts', 'utf8'));
const form = ts.createSourceFile('ScanForm.tsx', fs.readFileSync(root + 'ScanForm.tsx', 'utf8'),
  ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const statement = form.statements.find(node => ts.isVariableStatement(node)
  && node.declarationList.declarations.some(declaration => declaration.name.getText(form) === 'mapStatus'));
assert.ok(statement, 'Frozen baseline mapStatus must be present');
// Export only the exact declaration. No React rendering or rewritten verdict mapping.
const {mapStatus} = load('export ' + statement.getText(form));
const responses = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  let resultMappings = 0, jsonReads = 0, rejections = 0;
  for (const response of responses) {
    global.fetch = async (url, init) => {
      assert.ok(url.endsWith('/v1/analyze'));
      assert.equal(init.headers['X-MobileShield-Response-Version'], undefined);
      return {
        ok: response.status >= 200 && response.status < 300, status: response.status,
        statusText: 'Conflict', headers: new Headers({'Content-Type': 'application/json'}),
        text: async () => JSON.stringify(response.body),
        json: async () => { jsonReads++; return response.body; },
      };
    };
    await assert.rejects(async () => {
      const result = await api.analyzeUrl('https://synthetic.example');
      resultMappings++;
      mapStatus(result.verdict);
    }, error => {
      assert.ok(error instanceof api.ApiError);
      assert.equal(error.status, 409);
      assert.match(error.message, /client_upgrade_required/);
      assert.match(error.message, /refresh/i);
      rejections++;
      return true;
    });
  }
  assert.equal(resultMappings, 0);
  assert.equal(jsonReads, 0);
  // Positive controls prove this exact old client would otherwise reach its
  // known BENIGN fallback for canonical phishing and unknown on HTTP 200.
  const controls = [];
  for (const verdict of ['phishing', 'unknown']) {
    global.fetch = async () => new Response(JSON.stringify({verdict}), {
      status: 200, headers: {'Content-Type': 'application/json'},
    });
    controls.push(mapStatus((await api.analyzeUrl('https://synthetic.example')).verdict));
  }
  assert.deepEqual(controls, ['BENIGN', 'BENIGN']);
  process.stdout.write(JSON.stringify({upgrade_rejections: rejections, result_mappings: resultMappings,
    json_reads: jsonReads, baseline_positive_controls: controls}));
})().catch(error => { console.error(error); process.exitCode = 1; });
