(function () {
  'use strict';
  var notes = document.querySelectorAll('[data-personal-trial]');
  if (!notes.length) return;
  fetch('/api/v1/account/trial', {cache: 'no-store', credentials: 'omit'})
    .then(function (response) { return response.ok ? response.json() : {}; })
    .then(function (result) {
      if (result.available === true) notes.forEach(function (note) { note.hidden = false; });
    })
    .catch(function () {});
})();
