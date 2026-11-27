/* Доступность и суммы предложений приходят только с сервера. */
(function () {
  'use strict';
  function rub(minor) { return (minor / 100).toLocaleString('ru-RU', {minimumFractionDigits: 2, maximumFractionDigits: 2}) + ' ₽'; }
  function personal(offer, eligible) {
    return !!(offer && offer.enabled === true && (!eligible || offer.eligible === true) &&
      offer.discount_percent === 30 && offer.stackable === false && Array.isArray(offer.terms) &&
      [3, 6, 12].every(function (months) { return offer.terms.some(function (term) {
        return term && term.months === months && term.days === months * 30 && Number.isSafeInteger(term.base_amount_kopecks) &&
          Number.isSafeInteger(term.amount_kopecks) && term.amount_kopecks > 0 && term.amount_kopecks * 100 === term.base_amount_kopecks * 70;
      }); }));
  }
  function trial(offer) { return !!(offer && offer.enabled === true && offer.duration_hours === 24); }
  function club(offer) { return !!(offer && offer.enabled === true && offer.discount_percent === 30 && offer.duration_days === 90 && offer.limit === 20); }
  function fillPersonal(node, offer) {
    var term = offer.terms.find(function (term) { return term.months === 3; });
    node.querySelector('[data-offer-total]').textContent = rub(term.amount_kopecks) + ' за ' + term.days + ' дней';
    node.hidden = false;
  }
  window.veliqOffers = {personal: personal, trial: trial, club: club, rub: rub, fillPersonal: fillPersonal};
  var nodes = document.querySelectorAll('[data-offer-public]');
  if (!nodes.length) return;
  fetch('/api/v1/offers', {credentials: 'same-origin', cache: 'no-store', headers: {Accept: 'application/json'}})
    .then(function (response) { if (!response.ok) throw new Error('OFFERS_UNAVAILABLE'); return response.json(); })
    .then(function (data) {
      nodes.forEach(function (node) {
        var kind = node.getAttribute('data-offer-public');
        if (kind === 'personal' && personal(data.personal_first_purchase, false)) fillPersonal(node, data.personal_first_purchase);
        if (kind === 'trial' && trial(data.trial)) node.hidden = false;
        if (kind === 'club' && club(data.club_first20)) node.hidden = false;
      });
    }).catch(function () { nodes.forEach(function (node) { node.hidden = true; }); });
})();
