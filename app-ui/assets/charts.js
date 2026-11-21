/* VELIQ ping chart — маленькая функция без зависимостей.
   veliqPingChart(container, { series: [{ id:'direct'|'hel'|'swe', name, values:[мс...] }], height, unit })
   Рисует линии, сетку и подписи значений на конце линий (без легенды-загадки). */
(function (global) {
  function el(name, attrs, parent) {
    var n = document.createElementNS('http://www.w3.org/2000/svg', name);
    for (var k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(n);
    return n;
  }
  function median(a) { var s = a.slice().sort(function (x, y) { return x - y; }); var m = s.length >> 1; return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2); }

  function render(container, opts) {
    var series = opts.series || [];
    /* Ширина графика = ширина контейнера: подписи остаются читаемыми и на телефоне, а не сжимаются вместе с картинкой */
    var W = Math.max(280, Math.round(container.clientWidth) || 640), H = opts.height || 220, padL = 34, padR = W < 480 ? 100 : 136, padT = 12, padB = 24;
    var all = []; series.forEach(function (s) { all = all.concat(s.values); });
    var max = Math.max.apply(null, all), min = Math.min.apply(null, all);
    var top = Math.ceil((max + 5) / 20) * 20, bottom = Math.max(0, Math.floor((min - 5) / 20) * 20);
    var n = Math.max.apply(null, series.map(function (s) { return s.values.length; }));
    var x = function (i) { return padL + (W - padL - padR) * (i / (n - 1)); };
    var y = function (v) { return padT + (H - padT - padB) * (1 - (v - bottom) / (top - bottom)); };

    container.innerHTML = '';
    var svg = el('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'ping-chart', role: 'img',
      'aria-label': opts.label || ('Пинг, ' + series.map(function (s) { return s.name + ' — медиана ' + median(s.values) + ' мс'; }).join('; ')) }, container);
    var g = el('g', { class: 'grid' }, svg), ax = el('g', { class: 'axis' }, svg);
    var steps = 4;
    for (var i = 0; i <= steps; i++) {
      var v = bottom + (top - bottom) * i / steps, yy = y(v);
      el('line', { x1: padL, x2: W - padR, y1: yy, y2: yy }, g);
      var t = el('text', { x: padL - 8, y: yy + 4, 'text-anchor': 'end' }, ax); t.textContent = Math.round(v);
    }
    var t2 = el('text', { x: padL, y: H - 4 }, ax); t2.textContent = opts.startLabel || '60 с назад';
    var t3 = el('text', { x: W - padR, y: H - 4, 'text-anchor': 'end' }, ax); t3.textContent = opts.endLabel || 'сейчас';

    // подписи на концах линий, разведённые по вертикали
    var ends = series.map(function (s) { return { s: s, y: y(s.values[s.values.length - 1]) }; }).sort(function (a, b) { return a.y - b.y; });
    for (var k = 1; k < ends.length; k++) if (ends[k].y - ends[k - 1].y < 16) ends[k].y = ends[k - 1].y + 16;

    series.forEach(function (s) {
      var d = s.values.map(function (v, i) { return (i ? 'L' : 'M') + x(i).toFixed(1) + ' ' + y(v).toFixed(1); }).join(' ');
      el('path', { d: d, class: 'series series--' + s.id }, svg);
    });
    ends.forEach(function (e) {
      var s = e.s, last = s.values[s.values.length - 1];
      var color = getComputedStyle(container).getPropertyValue('--data-' + s.id) || 'currentColor';
      var lab = el('text', { x: W - padR + 10, y: e.y + 4, class: 'end-label', fill: color.trim() }, svg);
      lab.textContent = last + ' мс ' + s.name;
    });
    return svg;
  }
  function mount(container, opts) {
    var svg = render(container, opts);
    if (window.ResizeObserver && !container.__veliqRO) {
      var lastW = container.clientWidth;
      container.__veliqRO = new ResizeObserver(function () {
        var w = container.clientWidth; if (Math.abs(w - lastW) < 2) return; lastW = w; render(container, opts);
      });
      container.__veliqRO.observe(container);
    }
    return svg;
  }
  global.veliqPingChart = mount;
})(window);
