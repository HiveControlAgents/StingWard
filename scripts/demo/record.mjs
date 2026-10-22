// Maintainers only: regenerates the README images in docs/assets from real Stingward output.
// Needs Linux with Node 18+ and the `playwright` package (global is fine), ffmpeg, Python 3.9+ and network access (OSV, KEV, EPSS).
// Usage: node scripts/demo/record.mjs            (the 4 demo GIFs, with an MP4 and a poster of each for the website)   node scripts/demo/record.mjs --banners   (banners + social preview)
//        node scripts/demo/record.mjs --report   (three pages of the paid sample report for the website; also needs poppler-utils)
import { createRequire } from "module";
import { execFileSync, execSync } from "child_process";
import fs from "fs";
import os from "os";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const ASSETS = path.join(ROOT, "docs/assets");
const { chromium } = loadPlaywright();

function loadPlaywright() {
  for (const base of [ROOT + "/", execSync("npm root -g").toString().trim() + "/"]) {
    try { return createRequire(base)("playwright"); } catch {}
  }
  throw new Error("playwright not found: npm install -g playwright");
}

// ---------------------------------------------------------------- demo GIFs

const COLS = 110;
const DEMOS = [
  { name: "demo-skill-en", cmd: "stingward skill ./pdf-helper", args: ["skill", "./pdf-helper", "--lang", "en"], rows: 0, think: 700 },
  { name: "demo-skill-pt", cmd: "stingward skill ./pdf-helper", args: ["skill", "./pdf-helper", "--lang", "pt"], rows: 0, think: 700 },
  { name: "demo-app-en", cmd: "stingward ./my-saas", args: ["./my-saas", "--lang", "en"], rows: 34, think: 1600 },
  { name: "demo-app-pt", cmd: "stingward ./my-saas", args: ["./my-saas", "--lang", "pt"], rows: 34, think: 1600 },
];

function runDemo(dir, args) {
  // Under a pty so the CLI prints its real colors. The command shown in the GIF is the installed `stingward`.
  const cmd = ["python3", "-m", "stingward", ...args].map((a) => `'${a}'`).join(" ");
  let out;
  try {
    out = execFileSync("script", ["-qec", cmd, "/dev/null"], {
      cwd: dir, env: { ...process.env, PYTHONPATH: ROOT, PYTHONIOENCODING: "utf-8" }, maxBuffer: 1 << 24,
    });
  } catch (e) {
    if (e.status !== 1 || !e.stdout) throw e; // exit 1 = findings at or above --fail-on, which is the point of the demo
    out = e.stdout;
  }
  return out.toString("utf8").replace(/\r/g, "").replace(/\n+$/, "");
}

function parseAnsi(text) {
  // -> [[{t, cls}]] one array of spans per line
  const lines = [];
  let cur = [], state = { bold: false, fg: "" };
  const push = (t) => { if (t) cur.push({ t, cls: [state.bold ? "b" : "", state.fg].filter(Boolean).join(" ") }); };
  for (const part of text.split(/(\x1b\[[0-9;]*m)/)) {
    const m = part.match(/^\x1b\[([0-9;]*)m$/);
    if (m) {
      for (const code of (m[1] || "0").split(";").map(Number)) {
        if (code === 0) state = { bold: false, fg: "" };
        else if (code === 1) state.bold = true;
        else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97)) state.fg = "c" + code;
      }
      continue;
    }
    const pieces = part.split("\n");
    pieces.forEach((p, i) => { if (i > 0) { lines.push(cur); cur = []; } push(p); });
  }
  lines.push(cur);
  return lines;
}

function rng(seed) {
  let s = seed >>> 0;
  return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
}

function timeline(demo, lines) {
  // Each step is a screen state and how long it stays. Typing speed is pseudo-random but fixed, so reruns match.
  const r = rng(7);
  const steps = [];
  const st = (o, ms) => steps.push({ state: { typed: 0, cursor: false, shown: 0, done: false, ...o }, ms });
  st({ cursor: true }, 650); st({ cursor: false }, 380); st({ cursor: true }, 450);
  for (let i = 1; i <= demo.cmd.length; i++) st({ typed: i, cursor: true }, 38 + Math.round(r() * 52) + (demo.cmd[i - 1] === " " ? 40 : 0));
  st({ typed: demo.cmd.length, cursor: true }, 520);
  st({ typed: demo.cmd.length }, demo.think);
  // Reveal in chunks: the header, then one finding (block between blank lines) at a time.
  const n = demo.cmd.length;
  let i = 0;
  const blocks = [];
  while (i < lines.length) {
    let j = i;
    while (j < lines.length && lines[j].map((s) => s.t).join("").trim() !== "") j++;
    blocks.push(Math.min(j + 1, lines.length));
    i = j + 1;
  }
  blocks.forEach((end, k) => st({ typed: n, shown: end }, k === 0 ? 260 : demo.rows ? 480 : 320));
  for (let k = 0; k < 5; k++) { st({ typed: n, shown: lines.length, done: true, cursor: true }, 520); st({ typed: n, shown: lines.length, done: true }, 420); }
  st({ typed: n, shown: lines.length, done: true, cursor: true }, 700);
  return steps;
}

const TERM_CSS = `
  * { box-sizing: border-box; }
  html, body { margin: 0; background: #0d1117; }
  #win { display: inline-block; background: #0d1117; border: 1px solid #30363d; }
  #bar { height: 34px; background: #161b22; border-bottom: 1px solid #262c36; position: relative; display: flex; align-items: center; padding-left: 14px; gap: 8px; }
  #bar i { width: 12px; height: 12px; border-radius: 50%; display: block; }
  #bar span { position: absolute; left: 0; right: 0; text-align: center; font: 500 13px Inter, sans-serif; color: #8b949e; letter-spacing: .02em; }
  #screen { width: calc(${COLS}ch + 48px); padding: 14px 24px 16px; overflow: hidden;
            font: 14px/1.45 "JetBrains Mono", "Noto Color Emoji", monospace; color: #d1d7e0; font-variant-ligatures: none; }
  #inner { height: 100%; overflow: hidden; }
  .ln { white-space: pre-wrap; overflow-wrap: anywhere; min-height: 1.45em; }
  .p { color: #f5b83d; } .cmd { color: #f0f3f6; }
  .cur { display: inline-block; width: 1ch; height: 1.2em; vertical-align: -0.22em; background: #d1d7e0; }
  .b { font-weight: 700; }
  .c31 { color: #ff7b72; } .c32 { color: #7ee787; } .c33 { color: #e3b341; } .c34 { color: #79c0ff; }
  .c35 { color: #d2a8ff; } .c36 { color: #56d4dd; } .c37 { color: #e6edf3; } .c90 { color: #8b949e; }
`;

function termPage(lines, rows) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>${TERM_CSS}</style></head><body>
<div id="win"><div id="bar"><i style="background:#ff5f57"></i><i style="background:#febc2e"></i><i style="background:#28c840"></i><span>stingward</span></div>
<div id="screen"><div id="inner"></div></div></div>
<script>
const LINES = ${JSON.stringify(lines)};
const ROWS = ${rows};
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c]);
function hang(text) {
  // Wrapped lines continue under the text after their label ("   why: "), like a pretty-printed CLI.
  // Severity lines ("🟠 HIGH     title") continue under the title. Emoji count as 2 columns, like in a terminal.
  if (text.length <= ${COLS}) return 0;
  const sev = text.match(/^(\\p{Extended_Pictographic}\\s\\S+\\s+)/u);
  if (sev) return sev[1].length;
  const m = text.match(/^(\\s*[^\\s:][^:]{0,24}: )/);
  return m ? m[1].length : 0;
}
window.setup = (cmd, rowsToFit) => {
  window.CMDTEXT = cmd;
  const scr = document.getElementById("screen");
  const lh = parseFloat(getComputedStyle(scr).lineHeight);
  if (rowsToFit) { scr.style.height = (rowsToFit * lh + 30) + "px"; return rowsToFit; }
  // Fit everything: render the final state once and size the screen to it.
  window.render({ typed: cmd.length, shown: LINES.length, done: true, cursor: true });
  const h = document.getElementById("inner").scrollHeight;
  scr.style.height = (h + 30) + "px";
  return Math.round(h / lh);
};
window.render = (s) => {
  const out = [];
  const prompt = (t, cur) => '<div class="ln"><span class="p">$ </span><span class="cmd">' + esc(t) + '</span>' + (cur ? '<span class="cur"></span>' : '') + '</div>';
  out.push(prompt(window.CMDTEXT.slice(0, s.typed), s.cursor && !s.done));
  for (const spans of LINES.slice(0, s.shown)) {
    const text = spans.map((x) => x.t).join("");
    const h = hang(text);
    out.push('<div class="ln"' + (h ? ' style="padding-left:' + h + 'ch;text-indent:-' + h + 'ch"' : '') + '>' +
      spans.map((x) => x.cls ? '<span class="' + x.cls + '">' + esc(x.t) + '</span>' : esc(x.t)).join("") + '</div>');
  }
  if (s.done) out.push(prompt("", s.cursor));
  const inner = document.getElementById("inner");
  inner.innerHTML = out.join("");
  inner.scrollTop = inner.scrollHeight;
};
</script></body></html>`;
}

async function gif(browser, demo, lines, work) {
  const page = await browser.newPage({ viewport: { width: 1400, height: 1400 }, deviceScaleFactor: 1 });
  await page.setContent(termPage(lines, demo.rows));
  await page.evaluate(() => document.fonts.ready);
  await page.evaluate(([cmd, rows]) => window.setup(cmd, rows), [demo.cmd, demo.rows]);
  const win = await page.$("#win");
  const frames = [];
  let last = "";
  for (const { state, ms } of timeline(demo, lines)) {
    const key = JSON.stringify(state);
    if (key === last) { frames[frames.length - 1].ms += ms; continue; }
    last = key;
    await page.evaluate((s) => window.render(s), state);
    const file = path.join(work, `${demo.name}-${String(frames.length).padStart(4, "0")}.png`);
    await win.screenshot({ path: file });
    frames.push({ file, ms });
  }
  await page.close();
  const list = path.join(work, `${demo.name}.txt`);
  fs.writeFileSync(list, frames.map((f) => `file '${f.file}'\nduration ${(f.ms / 1000).toFixed(3)}`).join("\n") + `\nfile '${frames.at(-1).file}'\n`);
  const outFile = path.join(ASSETS, `${demo.name}.gif`);
  execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", list, "-fps_mode", "vfr",
    "-vf", "split[a][b];[a]palettegen=max_colors=256:stats_mode=diff:reserve_transparent=0[p];[b][p]paletteuse=dither=none:diff_mode=rectangle",
    "-loop", "0", outFile]);
  // The website plays the same recording as a muted video, with the final frame as its poster.
  execFileSync("ffmpeg", ["-y", "-loglevel", "error", "-i", outFile, "-movflags", "+faststart", "-pix_fmt", "yuv420p",
    "-vf", "pad=ceil(iw/2)*2:ceil(ih/2)*2:color=0x0d1117", "-c:v", "libx264", "-crf", "30", "-tune", "animation",
    "-preset", "veryslow", "-g", "600", "-an", outFile.replace(/\.gif$/, ".mp4")]);
  fs.copyFileSync(frames.at(-1).file, outFile.replace(/\.gif$/, ".png"));
  return { outFile, frames: frames.length };
}

async function demos() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "stingward-demo-"));
  const dir = path.join(work, "demo");
  execFileSync("python3", [path.join(ROOT, "scripts/demo/fixtures.py"), dir]);
  const browser = await chromium.launch();
  for (const demo of DEMOS) {
    const raw = runDemo(dir, demo.args);
    if (/sk-proj|Demo7Fake/.test(raw)) throw new Error(`${demo.name}: the fake key reached the output`);
    const lines = parseAnsi(raw);
    const { outFile, frames } = await gif(browser, demo, lines, work);
    console.log(`${path.relative(ROOT, outFile)}  ${frames} frames  ${(fs.statSync(outFile).size / 1024).toFixed(0)} KB  first line: ${lines[0].map((s) => s.t).join("")}`);
  }
  await browser.close();
  fs.rmSync(work, { recursive: true, force: true });
}

// ---------------------------------------------------------------- banners and social preview

const COPY = {
  en: { tag: "Security check for AI-built apps, Claude Code skills and MCP servers",
        chips: ["CVEs + KEV + EPSS", "Leaked secrets", "Supabase & Firebase", "MCP & agents", "Prompt injection"] },
  pt: { tag: "Verificação de segurança para apps feitos com IA, skills do Claude Code e servidores MCP",
        chips: ["CVEs + KEV + EPSS", "Segredos vazados", "Supabase e Firebase", "MCP e agentes", "Injeção de prompt"] },
  es: { tag: "Revisión de seguridad para apps hechas con IA, skills de Claude Code y servidores MCP",
        chips: ["CVEs + KEV + EPSS", "Secretos filtrados", "Supabase y Firebase", "MCP y agentes", "Inyección de prompts"] },
};

const THEMES = {
  dark: { bg: "#0d1117", hex: "rgba(245,184,61,0.075)", glow: "rgba(245,184,61,0.16)", word: "#f0f3f6", tag: "#9da7b3",
          chipBg: "rgba(245,184,61,0.08)", chipBorder: "rgba(245,184,61,0.32)", chipText: "#f5c55a" },
  light: { bg: "#ffffff", hex: "rgba(214,145,20,0.10)", glow: "rgba(245,184,61,0.20)", word: "#1f2328", tag: "#59636e",
           chipBg: "rgba(245,184,61,0.10)", chipBorder: "rgba(196,128,0,0.30)", chipText: "#8a5a00" },
};

function honeycomb(stroke) {
  // Pointy-top hexagons, r = 26: tile 45.03 x 78.
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="90.07" height="78"><g fill="none" stroke="${stroke}" stroke-width="1.3">
    <path d="M22.52 0 L45.03 13 V39 L22.52 52 L0 39 V13 Z"/><path d="M67.55 0 L90.07 13 V39 L67.55 52 L45.03 39 V13 Z"/>
    <path d="M45.03 39 L67.55 52 V78 M45.03 39 L22.52 52 V78 M0 39 V78 M90.07 39 V78"/></g></svg>`;
  return `url("data:image/svg+xml;base64,${Buffer.from(svg).toString("base64")}")`;
}

function bannerPage(lang, theme, logo) {
  const c = COPY[lang], t = THEMES[theme];
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  * { box-sizing: border-box; } html, body { margin: 0; }
  #b { width: 1600px; height: 400px; position: relative; overflow: hidden; background: ${t.bg};
       display: flex; align-items: center; padding: 0 104px; gap: 58px; font-family: Inter, sans-serif; }
  #b::before { content: ""; position: absolute; inset: -40px; background-image: ${honeycomb(t.hex)}; background-size: 90.07px 78px;
       -webkit-mask-image: radial-gradient(ellipse 75% 120% at 12% 50%, #000 0%, rgba(0,0,0,.55) 45%, transparent 85%); }
  #b::after { content: ""; position: absolute; left: -160px; top: -200px; width: 760px; height: 800px;
       background: radial-gradient(circle at 50% 50%, ${t.glow}, transparent 60%); }
  .logo { width: 236px; height: 236px; flex: none; position: relative; z-index: 1; }
  .logo svg { width: 100%; height: 100%; }
  .txt { position: relative; z-index: 1; min-width: 0; }
  h1 { margin: 0; font: 700 112px/1 "Inter Display", Inter, sans-serif; letter-spacing: -0.035em; color: ${t.word}; }
  p { margin: 18px 0 0; font: 400 31px/1.25 Inter, sans-serif; color: ${t.tag}; white-space: nowrap; letter-spacing: -0.005em; }
  .chips { display: flex; gap: 12px; margin-top: 30px; flex-wrap: nowrap; }
  .chips span { font: 500 18px/1 Inter, sans-serif; color: ${t.chipText}; background: ${t.chipBg}; border: 1px solid ${t.chipBorder};
       padding: 9px 16px; border-radius: 999px; white-space: nowrap; }
  </style></head><body><div id="b"><div class="logo">${logo}</div><div class="txt"><h1>Stingward</h1><p id="tag">${c.tag}</p>
  <div class="chips">${c.chips.map((x) => `<span>${x}</span>`).join("")}</div></div></div>
  <script>
    // Long taglines (pt, es) shrink to stay on one line. Block scope: the page is reused for every banner.
    {
      const p = document.getElementById("tag"), max = 1600 - 104 * 2 - 236 - 58;
      p.style.display = "inline-block";
      let s = 31; while (p.getBoundingClientRect().width > max && s > 22) { s -= 0.5; p.style.fontSize = s + "px"; }
      p.style.display = "";
    }
  </script></body></html>`;
}

function socialPage(logo) {
  return `<!doctype html><html><head><meta charset="utf-8"><style>
  * { box-sizing: border-box; } html, body { margin: 0; }
  #s { width: 1280px; height: 640px; position: relative; overflow: hidden; background: #0d1117; display: flex; flex-direction: column;
       align-items: center; justify-content: center; font-family: Inter, sans-serif; }
  #s::before { content: ""; position: absolute; inset: -40px; background-image: ${honeycomb("rgba(245,184,61,0.07)")}; background-size: 90.07px 78px;
       -webkit-mask-image: radial-gradient(ellipse 60% 70% at 50% 42%, #000 0%, rgba(0,0,0,.5) 50%, transparent 90%); }
  #s::after { content: ""; position: absolute; left: 340px; top: -260px; width: 600px; height: 760px;
       background: radial-gradient(circle at 50% 50%, rgba(245,184,61,0.15), transparent 62%); }
  .row { display: flex; align-items: center; gap: 34px; position: relative; z-index: 1; }
  .logo { width: 150px; height: 150px; } .logo svg { width: 100%; height: 100%; }
  h1 { margin: 0; font: 700 112px/1 "Inter Display", Inter, sans-serif; letter-spacing: -0.035em; color: #f0f3f6; }
  p { margin: 34px 0 0; font: 400 32px/1.3 Inter, sans-serif; color: #9da7b3; position: relative; z-index: 1; text-align: center; }
  code { margin-top: 44px; position: relative; z-index: 1; font: 500 22px/1 "JetBrains Mono", monospace; color: #f5c55a;
       background: rgba(245,184,61,0.08); border: 1px solid rgba(245,184,61,0.30); padding: 16px 26px; border-radius: 12px; }
  </style></head><body><div id="s"><div class="row"><div class="logo">${logo}</div><h1>Stingward</h1></div>
  <p>${COPY.en.tag}</p><code>pipx install stingward · npx stingward · /plugin install</code></div></body></html>`;
}

function shrinkPng(file) {
  // Lossy palette (256 colors) keeps the banners small; the glow is soft enough to survive it.
  execFileSync("python3", ["-c", `
import sys
from PIL import Image
im = Image.open(sys.argv[1]).convert("RGB")
im.quantize(colors=256, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.FLOYDSTEINBERG).save(sys.argv[1], optimize=True)
`, file]);
}

async function banners() {
  const logo = fs.readFileSync(path.join(ASSETS, "logo.svg"), "utf8").replace(/ width="64" height="64"/, "");
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1600, height: 640 }, deviceScaleFactor: 2 });
  for (const lang of Object.keys(COPY)) {
    for (const theme of Object.keys(THEMES)) {
      await page.setContent(bannerPage(lang, theme, logo));
      await page.evaluate(() => document.fonts.ready);
      const file = path.join(ASSETS, `banner-${lang}-${theme}.png`);
      await (await page.$("#b")).screenshot({ path: file });
      shrinkPng(file);
      console.log(`${path.relative(ROOT, file)}  ${(fs.statSync(file).size / 1024).toFixed(0)} KB`);
    }
  }
  await page.close();
  const social = await browser.newPage({ viewport: { width: 1280, height: 640 }, deviceScaleFactor: 1 });
  await social.setContent(socialPage(logo));
  await social.evaluate(() => document.fonts.ready);
  const file = path.join(ASSETS, "social-preview.png");
  await (await social.$("#s")).screenshot({ path: file });
  console.log(`${path.relative(ROOT, file)}  ${(fs.statSync(file).size / 1024).toFixed(0)} KB`);
  await browser.close();
}

// ---------------------------------------------------------------- pages of the paid sample report

// The website shows three pages of the paid sample report (site/build.py publishes it at example/full/ and
// pt/exemplo/completo/): the cover with the grade, the executive summary and the first page of the findings in detail.
// Each is the sample printed to A4 by Chromium, as a visitor's browser prints it, with the note on top left out by the
// report's own print style. A page is found by its heading, after the cover, whose contents list names them all.
const REPORT_PAGES = {
  en: { dir: "example/full", heads: { summary: "Executive summary", findings: "Findings in detail" } },
  pt: { dir: "pt/exemplo/completo", heads: { summary: "Resumo executivo", findings: "Achados em detalhe" } },
};
const REPORT_WIDTH = 900; // shown at about 450px, so it stays sharp on a 2x screen

async function reportPages() {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "stingward-report-"));
  const site = path.join(work, "site");
  execFileSync("python3", [path.join(ROOT, "site/build.py"), site, "--online"], { stdio: "ignore" });
  const browser = await chromium.launch();
  const page = await browser.newPage();
  for (const [lang, { dir, heads }] of Object.entries(REPORT_PAGES)) {
    await page.goto("file://" + path.join(site, dir, "index.html"));
    const pdf = path.join(work, `report-${lang}.pdf`);
    await page.pdf({ path: pdf, format: "A4", printBackground: true, preferCSSPageSize: true });
    const text = execFileSync("pdftotext", ["-layout", pdf, "-"]).toString().split("\f");
    if (/sk-proj|Demo7Fake/.test(text.join(""))) throw new Error(`report-${lang}: the fake key reached the report`);
    const found = { cover: 1 };
    for (const [name, head] of Object.entries(heads)) {
      const index = text.findIndex((t, i) => i > 0 && t.includes(head));
      if (index < 0) throw new Error(`report-${lang}: no page has the heading ${head}`);
      found[name] = index + 1;
    }
    for (const [name, number] of Object.entries(found)) {
      const base = path.join(ASSETS, `report-${lang}-${name}`);
      execFileSync("pdftoppm", ["-png", "-f", String(number), "-l", String(number), "-scale-to-x", String(REPORT_WIDTH),
        "-scale-to-y", "-1", "-singlefile", pdf, base]);
      shrinkPng(base + ".png");
      console.log(`${path.relative(ROOT, base)}.png  page ${number}  ${(fs.statSync(base + ".png").size / 1024).toFixed(0)} KB`);
    }
  }
  await browser.close();
  fs.rmSync(work, { recursive: true, force: true });
}

fs.mkdirSync(ASSETS, { recursive: true });
if (process.argv.includes("--banners")) await banners();
else if (process.argv.includes("--report")) await reportPages();
else await demos();
