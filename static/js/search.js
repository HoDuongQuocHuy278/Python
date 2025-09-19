/* static/js/search.js
 * Autocomplete "kiểu Google": gõ => gọi /api/suggest => hiện gợi ý ngay.
 */
window.addEventListener("DOMContentLoaded", () => {
    "use strict";
  
    const INPUT_ID = "tdc-search-input";
    const BOX_ID   = "tdc-suggest";
    const API_SUGGEST =
      document.querySelector('meta[name="suggest-endpoint"]')?.content || "/api/suggest";
    const MIN_CHARS = 1;     // gõ >= 1 ký tự thì gợi ý
    const DEBOUNCE  = 120;   // ms
  
    // ---------- helpers ----------
    const $ = (s, r=document) => r.querySelector(s);
    const create = (t, c) => { const el = document.createElement(t); if(c) el.className=c; return el; };
    const debounce = (fn, wait) => { let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), wait); }; };
    const escapeHTML = (s) => s.replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;'}[m]));
    const hiLite = (label, q) => {
      if (!q) return escapeHTML(label);
      const escQ = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      return escapeHTML(label).replace(new RegExp(escQ, "gi"), m => `<mark>${m}</mark>`);
    };
    const inside = (p, c) => p && c && (p===c || p.contains(c));
  
    const input =
      document.getElementById(INPUT_ID) ||
      $(".tdc-search input[name='q']") ||
      $(".tdc-search input");
  
    const box = document.getElementById(BOX_ID) || (() => {
      const el = create("div", "tdc-suggest"); el.id = BOX_ID; el.hidden = true;
      (input.closest("form") || input.parentElement).appendChild(el);
      return el;
    })();
  
    if (!input) return;
  
    // ARIA
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    box.setAttribute("role", "listbox");
  
    let items = [];
    let active = -1;
    let lastQ  = "";
  
    function hide(){ box.hidden = true; box.innerHTML = ""; items=[]; active=-1; input.setAttribute("aria-expanded","false"); }
    function show(){ if(items.length){ box.hidden=false; input.setAttribute("aria-expanded","true"); } else hide(); }
  
    function render(list, q){
      if(!list || !list.length){ hide(); return; }
      box.innerHTML = "";
      list.forEach((it, idx) => {
        const row = create("div", "item" + (idx===active ? " active" : ""));
        row.setAttribute("role", "option");
        row.dataset.index = String(idx);
        row.dataset.url = it.url || "";
  
        const type  = create("div", "type");
        type.textContent = it.type === "category" ? "Danh mục" : "Tin đăng";
  
        const label = create("div", "label");
        label.innerHTML = hiLite(it.label || "", q); // highlight an toàn
  
        row.appendChild(type);
        row.appendChild(label);
  
        row.addEventListener("mousedown", (e) => {
          e.preventDefault();
          if (it.url) window.location.href = it.url;
          else {
            const form = input.closest("form");
            if(form) form.submit();
            else window.location.href = `/search?q=${encodeURIComponent(input.value.trim())}`;
          }
        });
  
        row.addEventListener("mouseenter", () => {
          active = idx;
          Array.from(box.children).forEach((c, i)=>c.classList.toggle("active", i===active));
        });
  
        box.appendChild(row);
      });
      show();
    }
  
    async function suggest(q){
      if (!q || q.length < MIN_CHARS){ hide(); return; }
      try {
        const res = await fetch(`${API_SUGGEST}?q=${encodeURIComponent(q)}`, { credentials: "same-origin" });
        if (!res.ok) { hide(); return; }
        const data = await res.json();
        items = Array.isArray(data.items) ? data.items : [];
        active = -1;
        render(items, q);
      } catch { hide(); }
    }
    const debounced = debounce(suggest, DEBOUNCE);
  
    // events
    input.addEventListener("input", () => {
      const q = input.value.trim();
      if(q === lastQ) return;
      lastQ = q;
      debounced(q);
    });
    input.addEventListener("focus", () => { if(items.length) show(); });
    input.addEventListener("blur",  () => { setTimeout(hide, 120); }); // chờ click chọn
  
    input.addEventListener("keydown", (e) => {
      if (box.hidden || !items.length) return;
      if (e.key === "ArrowDown"){
        e.preventDefault(); active = (active + 1) % items.length; render(items, input.value.trim());
      } else if (e.key === "ArrowUp"){
        e.preventDefault(); active = (active - 1 + items.length) % items.length; render(items, input.value.trim());
      } else if (e.key === "Enter"){
        if (active >= 0 && items[active]){
          e.preventDefault();
          const url = items[active].url;
          if (url) window.location.href = url;
        } // nếu không chọn item -> để form submit bình thường
      } else if (e.key === "Escape"){
        hide();
      }
    });
  
    // nếu có text sẵn (back/forward) -> load gợi ý luôn
    if (input.value.trim().length >= MIN_CHARS) debounced(input.value.trim());
  });
  