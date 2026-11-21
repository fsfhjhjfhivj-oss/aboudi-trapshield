/*! ids-lite warning banner: <ids-warning-banner> (Web Component, Shadow DOM, no dependencies) */
(function () {
  'use strict';
  var script = document.currentScript;
  var BASE = '/ids';
  try { BASE = new URL(script.src).pathname.replace(/\/static\/banner\.js.*$/, ''); } catch (e) { /* keep default */ }

  var DEFAULT_MESSAGES = {
    unusual_activity: 'We noticed unusual activity from your connection. If this was you, no action is needed.',
    temporarily_blocked: 'Access from your connection is temporarily limited. Please try again later or contact support.'
  };
  var MIN_POLL_MS = 30000;
  var MAX_BACKOFF_MS = 300000;

  function debounce(fn, ms) { var t; return function () { var a = arguments; clearTimeout(t); t = setTimeout(function () { fn.apply(null, a); }, ms); }; }

  class IdsWarningBanner extends HTMLElement {
    constructor() {
      super();
      this._timer = null; this._failures = 0; this._dismissed = false;
      this._renderDebounced = debounce(this._render.bind(this), 250);
      this._onVisibility = this._onVisibility.bind(this);
    }
    connectedCallback() {
      if (!this.shadowRoot) this.attachShadow({ mode: 'open' });
      document.addEventListener('visibilitychange', this._onVisibility);
      this._poll();
    }
    disconnectedCallback() { document.removeEventListener('visibilitychange', this._onVisibility); clearTimeout(this._timer); }
    _onVisibility() { clearTimeout(this._timer); if (!document.hidden) this._poll(); }

    _poll() {
      var self = this;
      clearTimeout(this._timer);
      fetch(BASE + '/v1/public/status', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('status ' + r.status); return r.json(); })
        .then(function (s) {
          self._failures = 0;
          self._renderDebounced(s);
          self._schedule(Math.max(MIN_POLL_MS, (s.poll_after_sec || 60) * 1000));
        })
        .catch(function () {
          self._failures += 1; // exponential backoff, never hammer the server
          self._schedule(Math.min(MAX_BACKOFF_MS, MIN_POLL_MS * Math.pow(2, self._failures)));
        });
    }
    _schedule(ms) { var self = this; if (!document.hidden) this._timer = setTimeout(function () { self._poll(); }, ms); }

    _render(s) {
      var root = this.shadowRoot;
      while (root.firstChild) root.removeChild(root.firstChild);
      if (!s || s.level === 'none' || (this._dismissed && s.level === 'notice')) return;
      var blocked = s.level === 'blocked';
      var msgs = Object.assign({}, DEFAULT_MESSAGES, window.IDS_MESSAGES || {});
      var text = msgs[s.message_key] || DEFAULT_MESSAGES.unusual_activity;
      if (blocked && s.block_until) text += ' (' + new Date(s.block_until).toLocaleTimeString() + ')'; // static text: no live countdown spam for screen readers

      var style = document.createElement('style');
      style.textContent =
        ':host{position:fixed;inset:0 0 auto 0;z-index:2147483000;display:block}' +
        '.b{display:flex;gap:12px;align-items:center;padding:12px 16px;font:14px/1.4 system-ui,sans-serif;' +
        'background:' + (blocked ? '#7a1010' : '#fff3cd') + ';color:' + (blocked ? '#ffffff' : '#3d2e00') + '}' +
        'button{margin-inline-start:auto;min-width:44px;min-height:44px;cursor:pointer;border:1px solid currentColor;background:transparent;color:inherit;border-radius:6px;font-size:16px}' +
        'button:focus-visible{outline:3px solid currentColor;outline-offset:2px}' +
        '@media (prefers-reduced-motion:no-preference){.b{animation:in .2s ease-out}}' +
        '@keyframes in{from{transform:translateY(-100%)}}';

      var box = document.createElement('div');
      box.className = 'b';
      box.setAttribute('role', blocked ? 'alert' : 'status');
      box.setAttribute('aria-live', blocked ? 'assertive' : 'polite');
      var span = document.createElement('span');
      span.textContent = text; // textContent, never innerHTML
      box.appendChild(span);
      if (!blocked) {
        var btn = document.createElement('button');
        btn.type = 'button'; btn.setAttribute('aria-label', 'Dismiss'); btn.textContent = '\u2715';
        var self = this;
        btn.addEventListener('click', function () { self._dismissed = true; while (root.firstChild) root.removeChild(root.firstChild); });
        box.appendChild(btn);
      }
      root.appendChild(style); root.appendChild(box);
    }
  }

  if (!customElements.get('ids-warning-banner')) customElements.define('ids-warning-banner', IdsWarningBanner);
  function mount() { if (!document.querySelector('ids-warning-banner')) document.body.prepend(document.createElement('ids-warning-banner')); }
  if (document.body) mount(); else document.addEventListener('DOMContentLoaded', mount);
})();
