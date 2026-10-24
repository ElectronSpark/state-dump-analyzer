import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const topology = readFileSync(new URL('../assets/topology.js', import.meta.url), 'utf8');
const app = readFileSync(new URL('../assets/app.js', import.meta.url), 'utf8');
function extract(source, name) {
  const start = source.indexOf(`function ${name}(`);
  assert.ok(start >= 0);
  const tail = source.slice(start);
  const end = /\r?\n\}/.exec(tail);
  return tail.slice(0, end.index + end[0].length);
}

function navigation(basis, target) {
  const node = { member_id: 'member:d', node_id: 'd', revision_id: 'd/rev', navigation_target: target,
    plan: { plugin_set_id: 'set', plugin_id: 'plugin', projection_id: 'projection', status_perspective_id: 'status' } };
  const deps = {
    state: { query: { request: { basis, clock_policy: 'best_effort' } } },
    basisForNode: () => ({ queryTime: '17', clock_domain: 'member-native' }),
    location: { origin: 'http://localhost' }, safeNavigationTarget: value => value,
    currentReturnTarget: () => '/?time_ns=5#fabric',
  };
  const href = new Function(...Object.keys(deps), `${['applyNodeNavigationBasis', 'fallbackNodeHref', 'navigationHref'].map(name => extract(topology, name)).join('\n')}\nreturn navigationHref;`)(...Object.values(deps))(node);
  return new URL(href, 'http://localhost');
}

test('both node link paths preserve the requested UTC domain and exact time, including zero', () => {
  for (const time of ['0', '5']) {
    for (const target of [null, `/node?time_ns=${time}&clock_domain=member-native`]) {
      const url = navigation({ kind: 'absolute_time', time_ns: time }, target);
      assert.equal(url.searchParams.get('time_ns'), time);
      assert.equal(url.searchParams.get('clock_domain'), 'utc');
      assert.equal(url.searchParams.get('plugin_id'), 'plugin');
      assert.equal(url.searchParams.get('revision_id'), 'd/rev');
      assert.equal(url.searchParams.has('basis_offset_ns'), false);
    }
  }
});

test('both node link paths retain relative projection selection without adding an absolute time', () => {
  for (const target of [null, '/node?basis_kind=relative_to_watermark&basis_offset_ns=-7&time_ns=17']) {
    const url = navigation({ kind: 'relative_to_watermark', offset_ns: '-7' }, target);
    assert.equal(url.searchParams.get('basis_offset_ns'), '-7');
    assert.equal(url.searchParams.has('time_ns'), false);
    assert.equal(url.searchParams.get('projection_id'), 'projection');
  }
});

test('workspace bootstrap forwards revision and original basis, never a client resolved time', () => {
  const context = { nodeId: 'd', revisionId: 'd/rev', basisKind: 'absolute_time', timeNs: '5', clockDomain: 'utc', resolvedTime: '17' };
  const path = new Function('navigationContext', 'window', `${extract(app, 'bootstrapDatasetPath')}\nreturn bootstrapDatasetPath();`)(context, { location: { origin: 'http://localhost' } });
  const url = new URL(path, 'http://localhost');
  assert.equal(url.searchParams.get('revision_id'), 'd/rev');
  assert.equal(url.searchParams.get('time_ns'), '5');
  assert.equal(url.searchParams.has('resolvedTime'), false);
});

test('navigation banner distinguishes resolved native time, unresolved requests, and ordinary capture', () => {
  for (const mode of ['resolved', 'unresolved', 'capture']) {
    const context = { nodeId: 'd', ...(mode === 'capture' ? {} : { basisKind: 'relative_to_watermark', basisOffsetNs: '-7' }) };
    const banner = { classList: { toggle(_name, value) { banner.warning = value; } } };
    const deps = { navigationContext: context,
      state: { dataset: { node_snapshot: { resolved_time: mode === 'resolved' ? { local_time_ns: '3' } : null } }, cursorNs: 3n, resourceById: new Map() },
      hasTopologyNavigationContext: () => true, byId: () => banner, navigationTargetsLoadedMember: () => true, topologyLocalMember: () => null,
      formatDuration: value => value, safeLocalNavigationTarget: () => '/', escapeHtml: String,
    };
    new Function(...Object.keys(deps), `${extract(app, 'renderTopologyNavigationBanner')}\nrenderTopologyNavigationBanner();`)(...Object.values(deps));
    assert.equal(banner.warning, mode === 'unresolved');
    if (mode === 'resolved') assert.match(banner.innerHTML, /resolved native time 3 ns/);
    else if (mode === 'unresolved') assert.match(banner.innerHTML, /requested time unresolved/);
    else assert.doesNotMatch(banner.innerHTML, /requested time unresolved/);
  }
});
