'use strict';
// Tema claro/escuro: respeita o sistema por padrão; o botão grava a escolha neste navegador (localStorage, se disponível).
(function () {
  var KEY = 'verifica-theme', root = document.documentElement;
  var get = function () { try { return localStorage.getItem(KEY); } catch (e) { return null; } };
  var set = function (v) { try { localStorage.setItem(KEY, v); } catch (e) { /* sem armazenamento: vale só nesta página */ } };
  var saved = get();
  if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
  var current = function () {
    return root.getAttribute('data-theme') || (window.matchMedia && matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
  };
  document.addEventListener('DOMContentLoaded', function () {
    var b = document.getElementById('theme');
    if (!b) return;
    var label = function () { b.setAttribute('aria-label', current() === 'dark' ? 'Mudar para o tema claro' : 'Mudar para o tema escuro'); b.textContent = current() === 'dark' ? '☀' : '☾'; };
    label();
    b.addEventListener('click', function () { var n = current() === 'dark' ? 'light' : 'dark'; root.setAttribute('data-theme', n); set(n); label(); });
  });
})();
