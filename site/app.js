// Stingward site: copy buttons, the report picker, the stage slider, the index preview and the entrances.
// Everything on the page is readable without this file.

(() => {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    const label = button.querySelector("span");
    const idle = label.textContent;
    label.setAttribute("aria-live", "polite");
    button.addEventListener("click", async () => {
      let ok = false;
      try { await navigator.clipboard.writeText(button.dataset.copy); ok = true; } catch (_) { ok = false; }
      label.textContent = ok ? button.dataset.done : button.dataset.failed;
      button.classList.toggle("is-done", ok);
      clearTimeout(button.timer);
      button.timer = setTimeout(() => { label.textContent = idle; button.classList.remove("is-done"); }, 1800);
    });
  });
})();

// Three real reports: a tab list with arrow keys, one sheet shown at a time.
(() => {
  const tabs = [...document.querySelectorAll(".report__name")];
  if (!tabs.length) return;
  const select = (index, focus) => {
    tabs.forEach((tab, i) => {
      const on = i === index;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      const sheet = document.getElementById(tab.getAttribute("aria-controls"));
      sheet.hidden = !on;
      if (on) sheet.scrollTop = 0;
    });
    if (focus) tabs[index].focus();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(i));
    tab.addEventListener("keydown", (event) => {
      const step = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1 }[event.key];
      if (step) { event.preventDefault(); select((i + step + tabs.length) % tabs.length, true); }
      if (event.key === "Home") { event.preventDefault(); select(0, true); }
      if (event.key === "End") { event.preventDefault(); select(tabs.length - 1, true); }
    });
  });
})();

// How it works: one range input drives the clause, the detail and the fragment of the product.
(() => {
  const how = document.querySelector(".how");
  if (!how) return;
  const range = how.querySelector(".how__range");
  const clause = how.querySelector(".how__clause");
  const detail = how.querySelector(".how__detail");
  const control = how.querySelector(".how__control");
  const clauses = JSON.parse(how.dataset.clauses);
  const details = JSON.parse(how.dataset.details);
  const panes = how.querySelectorAll(".frag");
  const names = how.querySelectorAll(".how__names li");
  const calm = matchMedia("(prefers-reduced-motion: reduce)");
  let current = 0;
  const set = (i) => {
    if (i !== current && !calm.matches && clause.animate) {
      clause.animate([{ opacity: 0, transform: "translateY(10px)" }, { opacity: 1, transform: "none" }], { duration: 240, easing: "cubic-bezier(0.22, 1, 0.36, 1)" });
    }
    current = i;
    clause.textContent = clauses[i];
    detail.textContent = details[i];
    panes.forEach((pane) => { pane.hidden = Number(pane.dataset.stage) !== i; });
    names.forEach((name) => name.classList.toggle("is-on", Number(name.dataset.stage) === i));
    control.style.setProperty("--p", String(i / Number(range.max)));
    range.setAttribute("aria-valuetext", clauses[i]);
  };
  range.addEventListener("input", () => set(Number(range.value)));
  names.forEach((name) => name.addEventListener("click", () => { range.value = name.dataset.stage; set(Number(range.value)); }));
  set(0);
})();

// Where it runs: pointing at a row shows its preview in the one frame; a click keeps it there.
(() => {
  const root = document.querySelector(".index");
  if (!root) return;
  const rows = root.querySelectorAll(".index__row");
  const panes = root.querySelectorAll(".index__pane");
  let kept = 0;
  const show = (i) => {
    panes.forEach((pane) => pane.classList.toggle("is-shown", Number(pane.dataset.pane) === i));
    rows.forEach((row) => row.classList.toggle("is-current", Number(row.dataset.pane) === i));
  };
  rows.forEach((row) => {
    const i = Number(row.dataset.pane);
    row.addEventListener("pointerenter", () => show(i));
    row.addEventListener("focus", () => show(i));
    row.addEventListener("click", () => { kept = i; show(i); });
  });
  root.querySelector(".index__list").addEventListener("pointerleave", () => show(kept));
  root.addEventListener("focusout", (event) => { if (!root.contains(event.relatedTarget)) show(kept); });
  show(0);
})();

// Entrances: the parts of each section rise in turn, once. Content is never left hidden.
(() => {
  document.querySelectorAll("main > section").forEach((section) => {
    section.querySelectorAll("[data-reveal]").forEach((el, i) => el.style.setProperty("--i", String(Math.min(i, 8))));
  });
  const targets = document.querySelectorAll("[data-reveal]");
  if (!("IntersectionObserver" in window)) { targets.forEach((el) => el.classList.add("is-in")); return; }
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-in");
      io.unobserve(entry.target);
    }
  }, { threshold: 0.08 });
  targets.forEach((el) => io.observe(el));
  addEventListener("load", () => setTimeout(() => {
    targets.forEach((el) => { const r = el.getBoundingClientRect(); if (r.top < innerHeight && r.bottom > 0) el.classList.add("is-in"); });
  }, 2500));
})();

// The demo recordings play while they are on screen. With reduced motion they stay on their poster, the final frame.
(() => {
  const videos = document.querySelectorAll("video.demo");
  if (!videos.length || matchMedia("(prefers-reduced-motion: reduce)").matches || !("IntersectionObserver" in window)) return;
  const io = new IntersectionObserver((entries) => {
    for (const { target, isIntersecting } of entries) {
      if (isIntersecting) { target.preload = "auto"; target.play().catch(() => {}); } else target.pause();
    }
  }, { threshold: 0.35 });
  videos.forEach((video) => io.observe(video));
})();
