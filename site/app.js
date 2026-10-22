// Stingward site: the headline of the first screen, copy buttons, the menu on narrow screens, the two tab lists (the
// three real reports and where it runs), the entrances, the demo recordings and the ad label in links. Without this
// file every report and every preview is on the page, one after another, and the menu's links sit in a row under the
// bar.

// The headline of the first screen: one of the hooks in data-hooks, a different one on each visit. The page is built
// with the first, so that one shows without this script; ?hook=N (from 1) shows hook N, for a video or an ad that
// quotes it. The list only grows at the end, so a number keeps its hook.
(() => {
  const title = document.querySelector(".hero__title[data-hooks]");
  const lines = title ? title.querySelectorAll(".line > span") : [];
  let hooks = [];
  try { hooks = JSON.parse(title.dataset.hooks); } catch (_) { return; }
  if (!Array.isArray(hooks) || !hooks.length || lines.length !== 2) return;
  const asked = Number(new URLSearchParams(location.search).get("hook"));
  let index;
  if (Number.isInteger(asked) && asked >= 1 && asked <= hooks.length) {
    index = asked - 1;
  } else {
    let last = -1;
    try { const saved = localStorage.getItem("sw-hook"); if (saved !== null) last = Number(saved); } catch (_) {}
    index = Math.floor(Math.random() * hooks.length);
    if (hooks.length > 1 && index === last) index = (index + 1) % hooks.length;
    try { localStorage.setItem("sw-hook", String(index)); } catch (_) {}
  }
  hooks[index].forEach((text, i) => { lines[i].textContent = text; });
})();

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

// The menu below 1080px: the button opens the links under the bar; a link, the button again or Escape closes them.
(() => {
  const top = document.querySelector(".top");
  const button = top && top.querySelector(".menu");
  if (!button) return;
  const set = (open) => { top.classList.toggle("is-open", open); button.setAttribute("aria-expanded", String(open)); };
  button.addEventListener("click", () => set(button.getAttribute("aria-expanded") !== "true"));
  top.querySelectorAll(".nav a").forEach((link) => link.addEventListener("click", () => set(false)));
  addEventListener("keydown", (event) => {
    if (event.key === "Escape" && top.classList.contains("is-open")) { set(false); button.focus(); }
  });
})();

const calm = matchMedia("(prefers-reduced-motion: reduce)");

// A tab list with arrow keys, Home and End. The build marks the panels that start closed with data-off, so that
// without this script they all stay readable; here they become hidden panels.
const tablist = (list, onSelect) => {
  if (!list) return null;
  const tabs = [...list.querySelectorAll('[role="tab"]')];
  const panel = (tab) => document.getElementById(tab.getAttribute("aria-controls"));
  tabs.forEach((tab) => { const p = panel(tab); if (p.hasAttribute("data-off")) { p.removeAttribute("data-off"); p.hidden = true; } });
  let current = tabs.findIndex((tab) => tab.getAttribute("aria-selected") === "true");
  const select = (index, byKey) => {
    if (index === current) return;
    current = index;
    tabs.forEach((tab, i) => {
      const on = i === index;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      panel(tab).hidden = !on;
    });
    if (byKey) tabs[index].focus();
    if (onSelect) onSelect(panel(tabs[index]), byKey);
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", (event) => select(i, event.detail === 0));
    tab.addEventListener("keydown", (event) => {
      const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[event.key];
      if (step) { event.preventDefault(); select((i + step + tabs.length) % tabs.length, true); }
      if (event.key === "Home") { event.preventDefault(); select(0, true); }
      if (event.key === "End") { event.preventDefault(); select(tabs.length - 1, true); }
    });
  });
  return { current: () => panel(tabs[current]) };
};

// The three real reports. A pointer sees the chosen report print line by line; a key press shows it at once.
tablist(document.querySelector(".term__tabs"), (out, byKey) => {
  out.scrollTop = 0;
  out.classList.remove("is-in");
  if (byKey || calm.matches) return;
  [...out.children].forEach((line, i) => line.style.setProperty("--i", String(Math.min(i, 28))));
  void out.offsetWidth;
  out.classList.add("is-in");
});

// Where it runs: the recordings play while they are on screen and chosen. With reduced motion they stay on their
// poster, the final frame.
(() => {
  const view = document.querySelector(".dock__view");
  if (!view) return;
  const videos = [...view.querySelectorAll("video.demo")];
  let seen = false;
  const play = () => {
    videos.forEach((video) => {
      const shown = seen && !video.closest('[role="tabpanel"]').hidden && !calm.matches;
      if (shown) { video.preload = "auto"; video.play().catch(() => {}); } else video.pause();
    });
  };
  tablist(document.querySelector(".dock__tabs"), play);
  if (!("IntersectionObserver" in window)) return;
  new IntersectionObserver((entries) => { seen = entries[entries.length - 1].isIntersecting; play(); }, { threshold: 0.3 }).observe(view);
})();

// Entrances: the parts of each section rise in turn, once. Content is never left hidden.
(() => {
  document.querySelectorAll("main > section, main > div").forEach((section) => {
    section.querySelectorAll("[data-reveal]").forEach((el, i) => el.style.setProperty("--d", `${Math.min(i, 5) * 70}ms`));
  });
  const targets = document.querySelectorAll("[data-reveal]");
  if (!("IntersectionObserver" in window)) { targets.forEach((el) => el.classList.add("is-in")); return; }
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-in");
      io.unobserve(entry.target);
      near.unobserve(entry.target);
    }
  }, { threshold: 0.08 });
  // A part more than a screen away from the window stays plainly visible: only the parts about to come
  // into view wait for their entrance, so a page read without scrolling through it never shows a blank.
  const near = new IntersectionObserver((entries) => {
    for (const { target, isIntersecting } of entries) target.classList.toggle("is-far", !isIntersecting);
  }, { rootMargin: "100% 0px 100% 0px" });
  targets.forEach((el) => { io.observe(el); near.observe(el); });
  addEventListener("load", () => setTimeout(() => {
    targets.forEach((el) => { const r = el.getBoundingClientRect(); if (r.top < innerHeight && r.bottom > 0) el.classList.add("is-in"); });
  }, 2500));
})();

// The label of the ad or post that brought the visitor (?utm_source=instagram&utm_content=reel-1) goes on with the
// links to the site's other pages and to the buy page, so the order can keep it and show which ads sell. Nothing is
// stored on the visitor's device: the label lives only in the address.
(() => {
  const params = new URLSearchParams(location.search);
  const label = ["utm_source", "utm_medium", "utm_campaign", "utm_content"]
    .filter((key) => /^[A-Za-z0-9._-]{1,40}$/.test(params.get(key) || ""))
    .map((key) => [key, params.get(key)]);
  if (!label.length) return;
  document.querySelectorAll("a[href]").forEach((a) => {
    const url = new URL(a.getAttribute("href"), location.href);
    if (url.origin !== location.origin && !a.hasAttribute("data-buy")) return;
    if (url.pathname === location.pathname && url.hash) return;  // a jump within the page
    label.forEach(([key, value]) => url.searchParams.set(key, value));
    a.href = url.href;
  });
})();
