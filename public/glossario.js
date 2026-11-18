'use strict';
// Busca do glossário: filtra os cartões pelo texto digitado (sem acento, sem diferenciar maiúsculas).
(function () {
  const norm = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().trim();
  const q = document.getElementById('q');
  if (!q) return;
  const cards = [...document.querySelectorAll('.tcard')];
  const cats = [...document.querySelectorAll('.gcat')];
  const nores = document.getElementById('nores');
  function filter() {
    const terms = norm(q.value).split(/\s+/).filter(Boolean);
    let total = 0;
    for (const c of cards) {
      const hit = terms.every((t) => c.dataset.busca.includes(t));
      c.hidden = !hit;
      if (hit) total++;
    }
    for (const s of cats) s.hidden = !s.querySelector('.tcard:not([hidden])');
    nores.hidden = total > 0;
  }
  q.addEventListener('input', filter);
})();
