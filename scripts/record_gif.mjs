// Drive the wiretap UI (synthetic demo data only) in headless Chrome over the
// DevTools protocol and dump numbered PNG frames. Used by scripts/record_gif.sh.
// Node 20: run with --experimental-websocket (Node 22+ has WebSocket built in).
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync, copyFileSync, rmSync } from "node:fs";

const CHROME = process.env.CHROME || "google-chrome";
const OUT = process.env.FRAMES || "/tmp/wiretap-frames";
const UI = process.env.UI || "http://127.0.0.1:8788/";
const W = 1200, H = 720, FPS = +(process.env.FPS || 15);
const DBG = 9333;

rmSync(OUT, { recursive: true, force: true }); mkdirSync(OUT, { recursive: true });
const chrome = spawn(CHROME, ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
  `--remote-debugging-port=${DBG}`, `--window-size=${W},${H}`, "--user-data-dir=/tmp/wiretap-rec-profile",
  "--force-color-profile=srgb", "about:blank"], { stdio: "ignore" });
const sleep = ms => new Promise(r => setTimeout(r, ms));

let target;
for (let i = 0; i < 50 && !target; i++) {
  try { target = (await (await fetch(`http://127.0.0.1:${DBG}/json`)).json()).find(t => t.type === "page"); } catch { }
  if (!target) await sleep(200);
}
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let seq = 0; const pending = new Map(); const waiters = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  else if (m.method) waiters.filter(w => w.method === m.method).forEach(w => { w.fn(m); waiters.splice(waiters.indexOf(w), 1); }); };
const cdp = (method, params = {}) => new Promise((res, rej) => { const id = ++seq; pending.set(id, m => m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result)); ws.send(JSON.stringify({ id, method, params })); });
const once = method => new Promise(fn => waiters.push({ method, fn }));
const js = async expr => (await cdp("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true })).result.value;

await cdp("Page.enable");
await cdp("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: 1, mobile: false });
await cdp("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] });
const loaded = once("Page.loadEventFired");
await cdp("Page.navigate", { url: UI + "#id=3&tab=overview&theme=light" });
await loaded; await sleep(1500);

// overlay: caption pill + fake cursor (recording props only, not part of the app)
await js(`(()=>{const s=document.createElement('style');s.textContent=\`
#rec-cap{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);z-index:99999;background:rgba(32,26,20,.88);color:#fbf6ee;
 font:600 17px/1.3 -apple-system,'Segoe UI',Inter,Helvetica,Arial,sans-serif;padding:10px 18px;border-radius:999px;box-shadow:0 6px 24px rgba(0,0,0,.18);
 white-space:nowrap;transition:none}
:root[data-theme=dark] #rec-cap{background:rgba(251,246,238,.94);color:#1d1813}
#rec-hl{outline:3px solid #c0623b;outline-offset:3px;border-radius:10px}
#rec-cur{position:fixed;z-index:100000;width:22px;height:22px;pointer-events:none;left:0;top:0}
#rec-cur.down svg{transform:scale(.85);transform-origin:0 0}\`;document.head.appendChild(s);
const c=document.createElement('div');c.id='rec-cap';c.style.opacity=0;document.body.appendChild(c);
const k=document.createElement('div');k.id='rec-cur';k.innerHTML='<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2 L3 18 L7.5 14 L10.5 20.5 L13 19.4 L10.1 13 L16 13 Z" fill="#1d1813" stroke="#fff" stroke-width="1.4" stroke-linejoin="round"/></svg>';
document.body.appendChild(k);window.__cur={x:${W * 0.62},y:${H * 0.55}};k.style.transform='translate('+__cur.x+'px,'+__cur.y+'px)';})()`);

let n = 0;
async function frame() {
  const { data } = await cdp("Page.captureScreenshot", { format: "png" });
  const f = `${OUT}/f${String(n++).padStart(5, "0")}.png`; writeFileSync(f, Buffer.from(data, "base64")); return f;
}
async function hold(sec) { const f = await frame(); for (let i = 1; i < Math.round(sec * FPS); i++) copyFileSync(f, `${OUT}/f${String(n++).padStart(5, "0")}.png`); }
const ease = t => t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
async function caption(text, fade = 0.27) {
  const steps = Math.round(fade * FPS);
  for (let i = 1; i <= steps; i++) { await js(`(()=>{const c=document.getElementById('rec-cap');c.style.opacity=${1 - i / steps}})()`); await frame(); }
  await js(`(()=>{const c=document.getElementById('rec-cap');c.textContent=${JSON.stringify(text)}})()`);
  for (let i = 1; i <= steps; i++) { await js(`document.getElementById('rec-cap').style.opacity=${i / steps}`); await frame(); }
}
async function moveTo(sel, sec = 0.6) {
  const r = await js(`(()=>{const e=document.querySelector(${JSON.stringify(sel)});const b=e.getBoundingClientRect();return {x:b.left+b.width/2,y:b.top+b.height/2}})()`);
  const from = await js("window.__cur"); const steps = Math.round(sec * FPS);
  for (let i = 1; i <= steps; i++) { const t = ease(i / steps); const x = from.x + (r.x - from.x) * t, y = from.y + (r.y - from.y) * t;
    await js(`(()=>{__cur={x:${x},y:${y}};document.getElementById('rec-cur').style.transform='translate(${x}px,${y}px)'})()`); await frame(); }
}
async function click(sel) {
  await js(`document.getElementById('rec-cur').classList.add('down')`); await frame(); await frame();
  await js(`(async()=>{document.querySelector(${JSON.stringify(sel)}).click();document.getElementById('detail').scrollTop=0;await new Promise(r=>setTimeout(r,150))})()`);
  await js(`document.getElementById('rec-cur').classList.remove('down')`); await frame();
}
async function scrollDetail(to, sec) {
  const from = await js(`document.getElementById('detail').scrollTop`); const steps = Math.round(sec * FPS);
  const max = await js(`(()=>{const d=document.getElementById('detail');return d.scrollHeight-d.clientHeight})()`);
  const tgt = Math.min(to, max);
  for (let i = 1; i <= steps; i++) { await js(`document.getElementById('detail').scrollTop=${from + (tgt - from) * ease(i / steps)}`); await frame(); }
}
const tab = t => `.tab[data-t="${t}"]`;

// 1. overview: tiny message vs big request
await caption("You type “Reply OK”. Look how much actually leaves your laptop.");
await hold(2.3);
// 2. tools
await moveTo(tab("tools"), 0.45); await click(tab("tools"));
await caption("Every tool schema the agent ships, on every turn");
await hold(0.5); await scrollDetail(520, 1.2); await hold(0.4);
// 3. hidden chars: decoded tag-character instruction
await moveTo(tab("hidden"), 0.45); await click(tab("hidden"));
await caption("Invisible characters in a file it read? Decoded.");
await js(`document.querySelector('#pane table').id='rec-hl'`);
await hold(2.3);
// 4. PII
await moveTo(tab("pii"), 0.45); await click(tab("pii"));
await caption("Your email, paths and git identity, highlighted");
await hold(2.0);
// 5. dark mode
await moveTo(tab("overview"), 0.4); await click(tab("overview"));
await moveTo("#theme", 0.5);
await caption("Runs locally. Light or dark.");
await click("#theme"); await hold(1.8);

console.log(`wrote ${n} frames to ${OUT} at ${FPS} fps`);
ws.close(); chrome.kill();
process.exit(0);
