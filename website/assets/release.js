/* Версия и установщик всегда относятся к одному опубликованному релизу GitHub. */
(function () {
  'use strict';
  var links = document.querySelectorAll('[data-release-download]');
  var labels = document.querySelectorAll('[data-release-version]');
  if (!links.length && !labels.length) return;
  var endpoint = 'https://api.github.com/repos/buzzmean/veliq/releases/latest';
  var fallback = 'https://github.com/buzzmean/veliq/releases/latest';
  var cacheKey = 'veliq-public-release-v1';
  var ttl = 15 * 60 * 1000;

  function releaseInfo(data) {
    if (!data || data.draft || data.prerelease || typeof data.tag_name !== 'string' ||
        !/^v?[0-9][0-9A-Za-z._-]{0,63}$/.test(data.tag_name) || !Array.isArray(data.assets)) return null;
    var asset = data.assets.find(function (item) { return item.name === 'VELIQ-Setup.exe'; });
    if (!asset || !Number.isFinite(asset.size) || asset.size <= 0) return null;
    var url;
    try { url = new URL(asset.browser_download_url); } catch (e) { return null; }
    if (url.origin !== 'https://github.com' || url.username || url.password || url.search || url.hash ||
        url.pathname !== '/buzzmean/veliq/releases/download/' + encodeURIComponent(data.tag_name) + '/VELIQ-Setup.exe') return null;
    return { version: data.tag_name.replace(/^v/, ''), url: url.href, size: asset.size };
  }
  function show(data) {
    var info = releaseInfo(data);
    if (!info) return false;
    labels.forEach(function (el) { el.textContent = info.version; });
    links.forEach(function (el) { el.href = info.url; });
    document.querySelectorAll('[data-release-size]').forEach(function (el) {
      el.textContent = (info.size / 1048576).toLocaleString('ru-RU', { maximumFractionDigits: 1 }) + ' МБ';
    });
    document.querySelectorAll('[data-release-status]').forEach(function (el) { el.textContent = 'Последний опубликованный релиз'; });
    return true;
  }
  function unavailable() {
    labels.forEach(function (el) { el.textContent = 'на GitHub'; });
    links.forEach(function (el) { el.href = fallback; });
    document.querySelectorAll('[data-release-status]').forEach(function (el) {
      el.textContent = 'Версия и установщик доступны на странице релизов GitHub.';
    });
  }
  var cached;
  try { cached = JSON.parse(sessionStorage.getItem(cacheKey) || 'null'); } catch (e) {}
  if (cached && Number.isFinite(cached.at) && Date.now() >= cached.at && Date.now() - cached.at < ttl && show(cached.release)) return;
  var controller = new AbortController();
  var timer = setTimeout(function () { controller.abort(); }, 5000);
  fetch(endpoint, { signal: controller.signal, headers: { Accept: 'application/vnd.github+json' }, credentials: 'omit', referrerPolicy: 'no-referrer' })
    .then(function (response) { if (!response.ok) throw new Error('release unavailable'); return response.json(); })
    .then(function (data) {
      if (!show(data)) throw new Error('installer unavailable');
      try { sessionStorage.setItem(cacheKey, JSON.stringify({ at: Date.now(), release: data })); } catch (e) {}
    })
    .catch(unavailable)
    .then(function () { clearTimeout(timer); });
})();
