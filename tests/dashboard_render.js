// Harness di resa della dashboard. Carica in un contesto `vm` di node lo script vero di
// services/dashboard_app.html (tutti i blocchi <script>, nell'ordine, come un browser) con uno stub
// minimo del DOM, poi chiama le funzioni di resa vere sugli snapshot ricevuti: buildHtmlReport (report
// verso il cliente) e renderIntelTab (scheda Intel, storia dei cambiamenti compresa).
//
//   uso    : node dashboard_render.js < casi.json > risultato.json
//   stdin  : {"cases": [{"name", "domain", "client", "updated_at", "intel": {...}, "history": [...]}]}
//   stdout : {"blocks": n, "load_error": null | str,
//             "cases": {name: {"report": str | null, "intel_tab": str | null, "error": null | str}}}
//
// Nessuna rete, nessun file scritto: legge il sorgente della dashboard e stdin. Un'eccezione JS non si
// inghiotte mai: finisce in `error` del caso (o in `load_error` se è lo script a non caricarsi) e il
// test che la incontra fallisce. `setTimeout` e `fetch` sono finti e non eseguono nulla.
//
// Seconda modalità, `node dashboard_render.js --sinks` (SEC-34): invece di passare dagli snapshot, esegue
// scenari che chiamano UNA funzione della pagina per nome (anche una `async` che scrive nel DOM, come
// `renderClients` o `loadSummary`) e registra, per id, ciò che lo script assegna a `innerHTML` e a
// `textContent`. `api()` è sostituita da una funzione che risponde con i payload dello scenario.
//   stdin  : {"scenarios": [{"name", "call": "nomeFunzione", "args": [...], "globals": {"NOME": valore},
//                            "api": {"/percorso": payload}}]}
//   stdout : {"blocks": n, "load_error": null | str,
//             "scenarios": {name: {"returned": str | null, "sinks": {id: innerHTML}, "texts": {id: textContent},
//                                  "error": null | str}}}
// La modalità predefinita (senza argomenti) non cambia.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SOURCE = path.join(__dirname, "..", "services", "dashboard_app.html");

// Ogni proprietà di un elemento finto è un altro elemento finto, ogni chiamata ne restituisce uno;
// `value`, `innerHTML` e `textContent` sono stringhe vuote.
const element = () => new Proxy(function () {}, {
  get: (_target, key) => {
    if (key === Symbol.toPrimitive) return () => "";
    if (key === "value" || key === "innerHTML" || key === "textContent") return "";
    if (key === "classList") return { add() {}, remove() {}, toggle() {}, contains: () => false };
    if (key === "style" || key === "dataset") return {};
    return element();
  },
  set: () => true,
  apply: () => element(),
});

const storage = { getItem: () => null, setItem() {}, removeItem() {} };
const sandbox = {
  console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
  document: {
    getElementById: () => element(), querySelector: () => element(), querySelectorAll: () => [],
    createElement: () => element(), addEventListener() {}, body: element(),
  },
  sessionStorage: storage, localStorage: storage, navigator: {}, location: { hash: "", href: "" },
  fetch: () => new Promise(() => {}), setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0, clearInterval() {},
  requestAnimationFrame: () => 0, alert() {}, confirm: () => true, prompt: () => null,
  URL: { createObjectURL: () => "" }, Blob: function () {},
};
sandbox.window = sandbox;
const context = vm.createContext(sandbox);

// Gira dentro il contesto, così gli oggetti dello snapshot hanno gli stessi prototipi dello script.
const DRIVER = `(function () {
  const describe = e => {
    try { return (e && e.name ? e.name + ": " : "") + (e && e.message !== undefined ? e.message : String(e)); }
    catch (_) { return "eccezione non descrivibile"; }
  };
  const out = {};
  for (const c of JSON.parse(__input).cases) {
    const snapshot = { available: true, snapshot: { domain: c.domain, client: c.client, updated_at: c.updated_at, intel: c.intel },
                       history: c.history };
    const result = { report: null, intel_tab: null, error: null };
    try {
      result.report = buildHtmlReport({ client: c.client, report_generated: c.updated_at, cases: [], targets: [],
                                        watchlist: [], case_count: 0, intel_snapshots: { [c.domain]: snapshot } });
    } catch (e) { result.error = "buildHtmlReport: " + describe(e); }
    try {
      CURRENT_INTEL = snapshot;
      result.intel_tab = renderIntelTab();
    } catch (e) { result.error = (result.error ? result.error + " | " : "") + "renderIntelTab: " + describe(e); }
    out[c.name] = result;
  }
  return JSON.stringify(out);
})()`;

function main() {
  const page = fs.readFileSync(SOURCE, "utf8");
  const scripts = [...page.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const result = { blocks: scripts.length, load_error: null, cases: {} };
  if (!scripts.length) {
    result.load_error = "nessun blocco <script> in " + SOURCE;
  } else {
    try {
      for (const code of scripts) vm.runInContext(code, context, { filename: "dashboard_app.html", timeout: 20000 });
    } catch (e) {
      result.load_error = String(e && e.stack ? e.stack : e).split("\n").slice(0, 4).join(" | ");
    }
  }
  if (!result.load_error) {
    sandbox.__input = fs.readFileSync(0, "utf8");
    result.cases = JSON.parse(vm.runInContext(DRIVER, context, { filename: "driver.js", timeout: 20000 }));
  }
  process.stdout.write(JSON.stringify(result));
}

// ── Modalità `--sinks` ────────────────────────────────────────────────────────────────────────

const SINKS_MODE = process.argv.includes("--sinks");

// Come `element()`, ma `innerHTML` e `textContent` si registrano in `store[id]` quando lo script li assegna.
const recordingElement = (store, id) => {
  const slot = store[id] || (store[id] = { innerHTML: null, textContent: null });
  const base = element();
  return new Proxy(function () {}, {
    get: (_target, key) => {
      if (key === "innerHTML" || key === "textContent") return slot[key] === null ? "" : slot[key];
      return base[key];
    },
    set: (_target, key, value) => {
      if (key === "innerHTML" || key === "textContent") slot[key] = String(value);
      return true;
    },
    apply: () => element(),
  });
};

// Lo stdin di `--sinks` è scritto dai test, mai derivato da dati; `call` ammette solo funzioni dichiarate dalla pagina.
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;
const DENIED_NAMES = new Set(["eval", "Function", "constructor", "prototype", "__proto__"]);
const declaredFunctions = scripts => new Set(scripts.flatMap(
  code => [...code.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/g)].map(m => m[1])));
const describeError = e => {
  try { return (e && e.name ? e.name + ": " : "") + (e && e.message !== undefined ? e.message : String(e)); }
  catch (_) { return "eccezione non descrivibile"; }
};

// `api()` della pagina, sostituita: risponde con il payload del percorso (il più lungo fra quelli che
// ne sono prefisso) e rifiuta un percorso che lo scenario non ha previsto, così una chiamata inattesa
// non resta in attesa né riceve un valore inventato.
const API_STUB = `api = async function (path) {
  const payloads = JSON.parse(__api);
  const key = Object.keys(payloads).filter(k => String(path).startsWith(k)).sort((a, b) => b.length - a.length)[0];
  if (key === undefined) throw new Error("api(" + path + "): nessun payload nello scenario");
  return JSON.parse(JSON.stringify(payloads[key]));
};`;

async function runScenario(scenario, store, pageFunctions) {
  const out = { returned: null, sinks: Object.create(null), texts: Object.create(null), error: null };
  for (const id of Object.keys(store)) delete store[id];
  try {
    if (typeof scenario.call !== "string" || !IDENTIFIER.test(scenario.call)) {
      throw new Error("nome di funzione non valido: " + String(scenario.call));
    }
    if (DENIED_NAMES.has(scenario.call)) throw new Error("funzione non ammessa: " + scenario.call);
    if (!pageFunctions.has(scenario.call)) {
      throw new Error("funzione non dichiarata dallo script della pagina: " + scenario.call);
    }
    if (vm.runInContext("typeof " + scenario.call, context, { filename: "typeof.js" }) !== "function") {
      throw new Error("non è una funzione definita nel contesto della pagina: " + scenario.call);
    }
    sandbox.__api = JSON.stringify(scenario.api || {});
    vm.runInContext(API_STUB, context, { filename: "api_stub.js", timeout: 20000 });
    // Gli oggetti nascono dentro il contesto (JSON.parse lì), con i suoi prototipi, come per lo snapshot.
    for (const [name, value] of Object.entries(scenario.globals || {})) {
      if (!IDENTIFIER.test(name) || DENIED_NAMES.has(name)) throw new Error("nome di variabile non valido: " + name);
      sandbox.__value = JSON.stringify(value);
      vm.runInContext(name + " = JSON.parse(__value)", context, { filename: "globals.js", timeout: 20000 });
    }
    sandbox.__args = JSON.stringify(scenario.args || []);
    const returned = await vm.runInContext(scenario.call + "(...JSON.parse(__args))", context,
                                           { filename: "scenario.js", timeout: 20000 });
    out.returned = typeof returned === "string" ? returned : null;
  } catch (e) {
    out.error = describeError(e);
  }
  for (const [id, slot] of Object.entries(store)) {
    if (slot.innerHTML !== null) out.sinks[id] = slot.innerHTML;
    if (slot.textContent !== null) out.texts[id] = slot.textContent;
  }
  return out;
}

async function mainSinks() {
  const page = fs.readFileSync(SOURCE, "utf8");
  const scripts = [...page.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const result = { blocks: scripts.length, load_error: null, scenarios: Object.create(null) };
  const store = Object.create(null);
  sandbox.document.getElementById = id => recordingElement(store, id);
  if (!scripts.length) {
    result.load_error = "nessun blocco <script> in " + SOURCE;
  } else {
    try {
      for (const code of scripts) vm.runInContext(code, context, { filename: "dashboard_app.html", timeout: 20000 });
    } catch (e) {
      result.load_error = String(e && e.stack ? e.stack : e).split("\n").slice(0, 4).join(" | ");
    }
  }
  if (!result.load_error) {
    const pageFunctions = declaredFunctions(scripts);
    for (const scenario of JSON.parse(fs.readFileSync(0, "utf8")).scenarios) {
      result.scenarios[scenario.name] = await runScenario(scenario, store, pageFunctions);
    }
  }
  process.stdout.write(JSON.stringify(result));
}

const failSinks = e => {
  process.stderr.write("dashboard_render.js: " + String(e && e.stack ? e.stack : e) + "\n");
  process.exitCode = 2;
};

try {
  if (SINKS_MODE) mainSinks().catch(failSinks);
  else main();
} catch (e) {
  process.stderr.write("dashboard_render.js: " + String(e && e.stack ? e.stack : e) + "\n");
  process.exitCode = 2;
}
