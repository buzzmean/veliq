import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('../../website/assets/release.js', import.meta.url), 'utf8');
const now = 1804284000000;
const key = 'veliq-public-release-v1';
const makeRelease = tag => ({tag_name: tag, draft: false, prerelease: false, assets: [{
  name: 'VELIQ-Setup.exe', size: 57694241,
  browser_download_url: 'https://github.com/buzzmean/veliq/releases/download/' + tag + '/VELIQ-Setup.exe'
}]});
async function run({release = makeRelease('v0.3.577'), cache, error = false, httpOK = true, storageBlocked = false} = {}) {
  const elements = Object.fromEntries(['download', 'version', 'size', 'status'].map(name => [name, [{textContent:'на GitHub', href:'https://github.com/buzzmean/veliq/releases/latest'}]]));
  const storage = new Map(cache ? [[key, JSON.stringify(cache)]] : []);
  let requests = 0;
  const context = {
    document: {querySelectorAll: selector => elements[selector.slice('[data-release-'.length, -1)] || []},
    sessionStorage: {getItem: k => {if(storageBlocked)throw Error();return storage.get(k);}, setItem: (k,v) => {if(storageBlocked)throw Error();storage.set(k,v);}},
    URL, AbortController, Date: {now: () => now}, setTimeout: () => 1, clearTimeout: () => {},
    fetch: async (url, options) => {
      requests++;
      assert.equal(url, 'https://api.github.com/repos/buzzmean/veliq/releases/latest');
      assert.equal(options.credentials, 'omit');
      if(error)throw Error('offline');
      return {ok:httpOK, json:async()=>release};
    }
  };
  vm.runInNewContext(source, context);
  await new Promise(resolve => setImmediate(resolve));
  return {elements, requests, storage};
}
let result = await run();
assert.equal(result.elements.version[0].textContent, '0.3.577');
assert.equal(result.elements.download[0].href, makeRelease('v0.3.577').assets[0].browser_download_url);
assert.equal(result.requests, 1);
result = await run({release:makeRelease('v0.3.656'), cache:{at:now - 900001, release:makeRelease('v0.3.577')}});
assert.equal(result.elements.version[0].textContent, '0.3.656');
assert.match(result.elements.download[0].href, /v0\.3\.656\/VELIQ-Setup\.exe$/);
result = await run({cache:{at:now - 1000,release:makeRelease('v0.3.577')}});
assert.equal(result.requests, 0);
assert.equal(result.elements.version[0].textContent, '0.3.577');
for (const bad of [
  {...makeRelease('v0.3.656'), assets:[]},
  {...makeRelease('v0.3.656'), draft:true},
  {...makeRelease('v0.3.656'), prerelease:true},
  {...makeRelease('v0.3.656'), tag_name:'<script>'},
  {...makeRelease('v0.3.656'), assets:[{name:'VELIQ-Setup.exe',size:10,browser_download_url:'https://example.test/VELIQ-Setup.exe'}]},
  {...makeRelease('v0.3.656'), assets:[{name:'VELIQ-Setup.exe',size:10,browser_download_url:makeRelease('v0.3.577').assets[0].browser_download_url}]}
]) {
  result = await run({release:bad});
  assert.equal(result.elements.version[0].textContent, 'для Windows');
  assert.equal(result.elements.download[0].href, 'https://github.com/buzzmean/veliq/releases/latest/download/VELIQ-Setup.exe');
}
for (const options of [{error:true}, {httpOK:false}, {error:true,cache:{at:now-900001,release:makeRelease('v0.3.577')}}]) {
  result = await run(options);
  assert.equal(result.elements.download[0].href,'https://github.com/buzzmean/veliq/releases/latest/download/VELIQ-Setup.exe');
  assert.equal(result.elements.version[0].textContent,'для Windows');
}
result = await run({storageBlocked:true});
assert.equal(result.elements.version[0].textContent,'0.3.577');
console.log('RELEASE_METADATA_PASS: same-release version/asset, refresh/cache, invalid asset, prerelease/draft, offline/rate-limit, blocked storage');
