const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Execute the actual resolver with isolated environment and a quiet logger;
// importing the browser suite's logger would create unrelated persistent logs.
function resolver(env = {}) {
  const module = { exports: {} };
  const source = fs.readFileSync(path.join(__dirname, 'rum-sdk-version.js'), 'utf8');
  vm.runInNewContext(source, {
    module,
    __dirname,
    process: { env },
    require: (name) => name === './test-logger.js'
      ? { info() {}, warn() {} }
      : require(name),
  });
  return module.exports;
}

test('default CDN selection uses the committed pin without consulting metadata', async () => {
  const sdk = resolver();
  assert.equal(sdk.pinnedCdnSdkVersion(), '0.3.4');
  assert.equal(await sdk.resolveCdnSdkVersion({ request: { get() {
    assert.fail('default selection must not follow remote metadata');
  } } }), null);
});

test('explicit override probes both bundles', async () => {
  const urls = [];
  const sdk = resolver({ RUM_SDK_VERSION: '0.3.5' });
  const selected = await sdk.resolveCdnSdkVersion({ request: { async get(url) {
    urls.push(url);
    return { ok: () => true };
  } } });
  assert.equal(selected, '0.3.5');
  assert.equal(urls.length, 2);
  assert.ok(urls.some((url) => url.endsWith('openobserve-logs.js')));
});

test('incomplete CDN release falls back to the pin', async () => {
  const sdk = resolver({ RUM_SDK_VERSION: '0.3.5' });
  const selected = await sdk.resolveCdnSdkVersion({ request: { async get(url) {
    return { ok: () => !url.endsWith('openobserve-logs.js') };
  } } });
  assert.equal(selected, null);
});

test('latest metadata selection requires explicit opt-in', async () => {
  const sdk = resolver({ RUM_SDK_TRACK_LATEST: 'true' });
  const selected = await sdk.resolveCdnSdkVersion({ request: { async get(url) {
    return { ok: () => true, text: async () => 'https://browsersdk.openobserve.ai/0.4.3/openobserve-rum.js' };
  } } });
  assert.equal(selected, '0.4.3');
});
