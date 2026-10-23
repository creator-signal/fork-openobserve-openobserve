// RUM SDK version resolution
// --------------------------------------------------------------------------
// Decides which browser-SDK version the RUM E2E suite should exercise. All
// resolution is BEST-EFFORT: the suite must never go red because a registry,
// README, or CDN lookup failed — the committed pin is always a valid answer.
//
// CDN path (script tags served from browsersdk.openobserve.ai):
//   1. Committed sample pin by default; explicit RUM_SDK_VERSION overrides it.
//   2. With RUM_SDK_TRACK_LATEST=true, the version published in the SDK README:
//      of truth for CDN releases (the CDN itself has no "latest" alias):
//      https://github.com/openobserve/browser-sdk/blob/openobserve/README.md
//   Every candidate is PROBED against the live CDN before being accepted; an
//   unprovisioned/unreachable candidate falls back to the version pinned in
//   the committed sample HTML (fixtures/rum/cdn-sample), and finally to null
//   (= serve the sample as committed).
//
// NPM path (@openobserve/browser-rum + @openobserve/browser-logs):
//   Hermetic by default — the fixture builds from the exact versions pinned in
//   fixtures/rum/npm-app/package.json + package-lock.json. Tracking the
//   registry dist-tag `latest` is OPT-IN via RUM_SDK_TRACK_LATEST=true
//   (RUM_SDK_VERSION still overrides), so CI never depends on the registry
//   answering, only on installing the locked versions.

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const testLogger = require('./test-logger.js');

const README_URL =
  'https://raw.githubusercontent.com/openobserve/browser-sdk/openobserve/README.md';
const SAMPLE_INDEX_HTML = path.resolve(
  __dirname,
  '../../fixtures/rum/cdn-sample/index.html',
);

/** Highest x.y.z among the given version strings (numeric compare per part). */
function maxSemver(versions) {
  const parse = (v) => v.split('.').map((n) => parseInt(n, 10));
  return versions.reduce((best, v) => {
    if (!best) return v;
    const [a, b] = [parse(v), parse(best)];
    for (let i = 0; i < 3; i += 1) {
      if (a[i] !== b[i]) return a[i] > b[i] ? v : best;
    }
    return best;
  }, null);
}

/**
 * The SDK version pinned in the committed sample app HTML — the always-valid
 * fallback the suite can run against with no network lookups at all.
 * @returns {string|null}
 */
function pinnedCdnSdkVersion() {
  try {
    const html = fs.readFileSync(SAMPLE_INDEX_HTML, 'utf8');
    const m = html.match(/browsersdk\.openobserve\.ai\/(\d+\.\d+\.\d+)\//);
    return m ? m[1] : null;
  } catch {
    return null;
  }
}

/**
 * Probe both CDN bundles: a RUM-only release cannot initialize the Logs fixture.
 * @returns {Promise<boolean>}
 */
async function cdnServesVersion(page, version) {
  try {
    for (const bundle of ['rum', 'logs']) {
      const res = await page.request.get(
        `https://browsersdk.openobserve.ai/${version}/openobserve-${bundle}.js`,
        { timeout: 15000 },
      );
      if (!res.ok()) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Latest CDN version advertised in the browser-sdk README, or null. */
async function readmeLatestVersion(page) {
  try {
    const res = await page.request.get(README_URL, { timeout: 15000 });
    if (!res.ok()) {
      testLogger.warn('browser-sdk README fetch non-OK', { status: res.status() });
      return null;
    }
    const md = await res.text();
    const versions = [...md.matchAll(/browsersdk\.openobserve\.ai\/(\d+\.\d+\.\d+)\//g)]
      .map((m) => m[1]);
    return maxSemver([...new Set(versions)]);
  } catch (e) {
    testLogger.warn('browser-sdk README fetch failed', { error: e.message });
    return null;
  }
}

/**
 * Resolve the CDN bundle version to test — best-effort with a committed
 * pinned fallback. Candidates (README latest, RUM_SDK_VERSION) are verified
 * against the live CDN before being accepted, so an unpublished "latest"
 * never turns the suite red; it just degrades to the committed pin.
 * @param {import('@playwright/test').Page} page any live page (used for HTTP)
 * @returns {Promise<string|null>} version like "0.3.4", or null for "as pinned"
 */
async function resolveCdnSdkVersion(page) {
  const pinned = pinnedCdnSdkVersion();
  const candidates = [];
  if (process.env.RUM_SDK_VERSION) {
    candidates.push({ version: process.env.RUM_SDK_VERSION, source: 'RUM_SDK_VERSION env' });
  }
  // A remote README is mutable and can select a new SDK API without a source
  // change. Qualify the committed sample by default; explicit tracking remains
  // available to detect upstream drift (as with the NPM fixture).
  if (process.env.RUM_SDK_TRACK_LATEST === 'true') {
    const readmeLatest = await readmeLatestVersion(page);
    if (readmeLatest) candidates.push({ version: readmeLatest, source: 'browser-sdk README' });
  }

  for (const { version, source } of candidates) {
    if (pinned && version === pinned) break; // same as the pin — nothing to rewrite
    if (await cdnServesVersion(page, version)) {
      testLogger.info('CDN SDK version resolved', { version, source });
      return version;
    }
    testLogger.warn('CDN does not serve candidate version — falling back', {
      version,
      source,
    });
  }

  testLogger.info('Testing the SDK version pinned in the committed sample app', {
    version: pinned || 'unknown',
  });
  return null; // keep whatever the committed sample HTML pins
}

/**
 * Resolve the npm package version to test. Hermetic by default: returns null
 * (= build from the committed package.json + lockfile pins). Registry
 * dist-tag tracking is opt-in via RUM_SDK_TRACK_LATEST=true.
 * @returns {string|null} version like "0.3.4", or null for "use the pinned deps"
 */
function resolveNpmSdkVersion() {
  if (process.env.RUM_SDK_VERSION) {
    testLogger.info('NPM SDK version from RUM_SDK_VERSION env override', {
      version: process.env.RUM_SDK_VERSION,
    });
    return process.env.RUM_SDK_VERSION;
  }
  if (process.env.RUM_SDK_TRACK_LATEST !== 'true') {
    return null; // default: hermetic — versions pinned in the fixture lockfile
  }

  try {
    const out = execSync('npm view @openobserve/browser-rum version', {
      encoding: 'utf8',
      timeout: 30000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (/^\d+\.\d+\.\d+/.test(out)) {
      testLogger.info('NPM SDK version resolved from registry', { version: out });
      return out;
    }
  } catch (e) {
    testLogger.warn('npm registry version lookup failed — using pinned deps', {
      error: e.message,
    });
  }
  return null;
}

module.exports = {
  resolveCdnSdkVersion,
  resolveNpmSdkVersion,
  pinnedCdnSdkVersion,
  maxSemver,
};
