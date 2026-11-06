// Valutatore dei gestori inline della dashboard (SEC-37). Due modalità.
//
// Modalità predefinita: non carica la pagina. Riceve il testo di ogni attributo `on*` GIA' DECODIFICATO dal
// parser HTML (lo decodifica il test con html.parser, come un browser) e lo esegue, uno per volta, in un
// contesto `vm` NUOVO in cui esistono soltanto stub che registrano le chiamate: le funzioni dichiarate dalla
// pagina e la sonda `probe37`, che esiste solo qui. Se fra le chiamate compare la sonda, il testo di un dato
// ha chiuso la stringa o l'argomento del gestore ed e' stato eseguito.
//
//   uso    : node dashboard_handlers.js < gestori.json > risultato.json
//   stdin  : {"functions": [nomi delle funzioni della pagina], "this_value": "testo",
//             "handlers": [{"id", "code"}]}
//   stdout : {"results": {id: {"error": null | str,
//                               "calls": [{"fn", "args": [{"type": typeof | "null", "value": ...}]}]}}}
//
// Nessuna rete, nessun file scritto, nessun DOM. Un `vm` NON e' un confine di sicurezza: qui il contesto e'
// isolato quanto basta per input scritti dai test (valori ostili inerti, che chiamano solo la sonda), non per
// testo di terzi. Per questo: il sandbox ha prototipo nullo; nomi e `this.value` entrano come testo JSON, si
// leggono DENTRO il contesto e si cancellano subito; gli stub nascono dentro il contesto, cosi' il loro
// `constructor` e' quello del contesto; il contesto rifiuta `eval` e `Function` (generazione di codice da
// stringhe). Un tentativo di raggiungere l'host (`constructor.constructor(...)`) da' un errore.
// Il codice di un gestore e' compilato come corpo di funzione con parametro `event` (come fa un browser):
// una `}` o un `)` di troppo e' un SyntaxError, non esce dal corpo. `this.value` vale `this_value`.
//
// Modalità `--helper NOME`: carica gli script veri della pagina (stub minimo del DOM, come
// `dashboard_render.js`) e chiama la funzione-helper NOME su valori che JSON non sa rappresentare
// (`undefined`, una funzione, un simbolo) oltre che su valori JSON. Il valore non e' mai codice: e' scelto
// da un elenco chiuso di tipi e costruito dentro il contesto. Il contesto della pagina contiene stub
// dell'host e vi gira il codice del repo, non testo di terzi.
//
//   uso    : node dashboard_handlers.js --helper NOME < valori.json > risultato.json
//   stdin  : {"values": [{"id", "kind": "undefined" | "null" | "function" | "symbol" | "json", "json": valore}]}
//   stdout : {"load_error": null | str,
//             "results": {id: {"type": typeof del risultato, "value": risultato | null, "error": null | str}}}
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const PROBE = "probe37";
const IDENTIFIER = /^[A-Za-z_$][\w$]*$/;
const DENIED_NAMES = new Set(["eval", "Function", "constructor", "prototype", "__proto__"]);
const TIMEOUT_MS = 1000;
const SOURCE = path.join(__dirname, "..", "services", "dashboard_app.html");

// Gira dentro il contesto: legge nomi e `this.value` (testo JSON), li cancella, e registra nome e argomenti
// (tipo e valore) di ogni chiamata.
const SETUP = `(function () {
  const names = JSON.parse(__names_json);
  const thisValue = JSON.parse(__this_json);
  delete globalThis.__names_json;
  delete globalThis.__this_json;
  const calls = [];
  const describe = a => {
    const type = typeof a;
    if (a === null) return { type: "null", value: null };
    if (type === "string" || type === "boolean") return { type, value: a };
    if (type === "number") return { type, value: Number.isFinite(a) ? a : String(a) };
    return { type, value: null };
  };
  for (const name of names) {
    globalThis[name] = function () { calls.push({ fn: name, args: Array.prototype.map.call(arguments, describe) }); };
  }
  globalThis.__calls = () => JSON.stringify(calls);
  globalThis.__this = { value: thisValue };
  globalThis.__event = {};
})()`;

const describeError = e => {
  try { return (e && e.name ? e.name + ": " : "") + (e && e.message !== undefined ? e.message : String(e)); }
  catch (_) { return "eccezione non descrivibile"; }
};

function evaluate(code, names, thisValue) {
  const out = { error: null, calls: [] };
  const context = vm.createContext(Object.create(null), { codeGeneration: { strings: false, wasm: false } });
  try {
    context.__names_json = JSON.stringify(names);
    context.__this_json = JSON.stringify(thisValue);
    vm.runInContext(SETUP, context, { filename: "setup.js", timeout: TIMEOUT_MS });
    context.__handler = vm.compileFunction(code, ["event"], { parsingContext: context, filename: "handler.js" });
    vm.runInContext("__handler.call(__this, __event)", context, { filename: "call.js", timeout: TIMEOUT_MS });
  } catch (e) {
    out.error = describeError(e);
  }
  try {
    out.calls = JSON.parse(vm.runInContext("__calls()", context, { filename: "calls.js", timeout: TIMEOUT_MS }));
  } catch (e) {
    out.error = (out.error ? out.error + " | " : "") + "chiamate illeggibili: " + describeError(e);
  }
  return out;
}

function main() {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  const names = [...new Set([PROBE, ...input.functions])];
  for (const name of names) {
    if (!IDENTIFIER.test(name)) throw new Error("nome di funzione non valido: " + name);
  }
  const results = Object.create(null);
  for (const handler of input.handlers) {
    results[handler.id] = evaluate(String(handler.code), names, String(input.this_value));
  }
  process.stdout.write(JSON.stringify({ results }));
}

// ── Modalità `--helper` ───────────────────────────────────────────────────────────────────────

// Ogni proprietà di un elemento finto è un altro elemento finto, ogni chiamata ne restituisce uno;
// `value`, `innerHTML` e `textContent` sono stringhe vuote (come in `dashboard_render.js`).
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
const pageSandbox = () => {
  const sandbox = {
    console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
    document: {
      getElementById: () => element(), querySelector: () => element(), querySelectorAll: () => [],
      createElement: () => element(), addEventListener() {}, body: element(),
    },
    sessionStorage: storage, localStorage: storage, navigator: {}, location: { hash: "", href: "" },
    fetch: () => new Promise(() => {}), setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
    clearInterval() {}, requestAnimationFrame: () => 0, alert() {}, confirm: () => true, prompt: () => null,
    URL: { createObjectURL: () => "" }, Blob: function () {},
  };
  sandbox.window = sandbox;
  return sandbox;
};

// Il valore si costruisce dentro il contesto da un elenco chiuso: nessun testo dello stdin diventa codice.
const VALUE_SOURCES = {
  undefined: "undefined",
  null: "null",
  function: "(function () {})",
  symbol: "Symbol('x')",
  json: "JSON.parse(__json)",
};

function mainHelper(name) {
  if (!IDENTIFIER.test(name) || DENIED_NAMES.has(name)) throw new Error("nome di helper non valido: " + name);
  const page = fs.readFileSync(SOURCE, "utf8");
  const scripts = [...page.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  const result = { load_error: null, results: Object.create(null) };
  const sandbox = pageSandbox();
  const context = vm.createContext(sandbox, { codeGeneration: { strings: false, wasm: false } });
  try {
    if (!scripts.length) throw new Error("nessun blocco <script> in " + SOURCE);
    for (const code of scripts) vm.runInContext(code, context, { filename: "dashboard_app.html", timeout: 20000 });
  } catch (e) {
    result.load_error = String(e && e.stack ? e.stack : e).split("\n").slice(0, 4).join(" | ");
  }
  if (!result.load_error) {
    for (const value of JSON.parse(fs.readFileSync(0, "utf8")).values) {
      const out = { type: null, value: null, error: null };
      try {
        if (!Object.hasOwn(VALUE_SOURCES, value.kind)) throw new Error("tipo di valore non ammesso: " + value.kind);
        if (vm.runInContext("typeof " + name, context, { filename: "typeof.js" }) !== "function") {
          throw new Error("non è una funzione definita nel contesto della pagina: " + name);
        }
        sandbox.__json = JSON.stringify(value.json === undefined ? null : value.json);
        const returned = vm.runInContext(name + "(" + VALUE_SOURCES[value.kind] + ")", context,
                                         { filename: "helper.js", timeout: TIMEOUT_MS });
        out.type = typeof returned;
        out.value = typeof returned === "string" ? returned : null;
      } catch (e) {
        out.error = describeError(e);
      }
      result.results[value.id] = out;
    }
  }
  process.stdout.write(JSON.stringify(result));
}

try {
  const at = process.argv.indexOf("--helper");
  if (at >= 0) mainHelper(String(process.argv[at + 1]));
  else main();
} catch (e) {
  process.stderr.write("dashboard_handlers.js: " + String(e && e.stack ? e.stack : e) + "\n");
  process.exitCode = 2;
}
