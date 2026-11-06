"""CODE-74 — la scheda Intel distingue «nessuno», «non determinato» e «riportato» per sottodomini e selettori DKIM.

`/dns` prova uno per uno 25 sottodomini e 18 selettori DKIM: `subdomains = {tested, active, unknown}` e
`email_auth.dkim = {selectors_found, selectors_tested, records, selectors_unknown}`. Un nome in `unknown` o in
`selectors_unknown` non ha avuto risposta: non è «assente». Con il riporto per nome (COL-31) un nome trovato nel ciclo
precedente e senza risposta in questo resta in `active`/`selectors_found` con il dato precedente, resta anche in
`unknown`, e il marcatore di sezione lo dice: `subdomains.carried_over` ed `email_auth.dkim.carried_over`, entrambi
`{nome: {observed_at, carried_at}}`. Una resa che legge solo `active` e `selectors_found` mostra uguali, byte per
byte, «nessun nome trovato», «nessun nome determinato» e una sezione senza dati; presenta un nome riportato come
osservato nel ciclo, senza data; e il report dice «DNS ok».

Contratto della vista, fissato qui (scheda Intel, blocco `data-sec="dns"`; report, riga «Module status»):
  * sottodomini: il blocco che si apre con il titolo «Subdomains…»; una riga di tabella per nome attivo, con il
    nome nella prima cella. Selettori DKIM: le righe della tabella DNS con prima cella «DKIM»;
  * «nessun…» seguito, come primo numero, dal numero dei nomi provati (`tested`, `selectors_tested`): solo con
    nulla di trovato e nulla di non determinato, e solo se la sezione ha la lista dei non determinati. Sulla stessa
    riga, dopo, «osserva…» e la data della sezione (`dns.timestamp` se è una stringa non vuota, escapata e tagliata;
    altrimenti «data ignota»): nel guasto totale, o senza risposta da `/dns`, la sezione salvata è quella del ciclo
    precedente, intera, e un «nessuno» senza data sembrerebbe del ciclo;
  * «non determinat…» seguito, come primo numero, dal numero dei nomi in `unknown`/`selectors_unknown` che non sono
    trovati, ed elencati per nome (anche dentro un `<details>`);
  * un nome riportato porta «riportat…» e la data dell'ultima osservazione (`observed_at` se è una stringa non
    vuota, escapata e tagliata; altrimenti «data ignota») dopo il nome e prima del nome seguente: nella sua riga
    per un sottodominio, nell'elenco dei trovati per un selettore. Un nome non riportato non porta «riportat»;
  * ogni nome compare una volta: un riportato, in `active` e in `unknown`, non si conta fra i non determinati;
  * dati completi (nulla di non determinato né di riportato): la resa è identica, byte per byte, a quella delle sole
    liste dei trovati (`{active}`, `{selectors_found}`). Nessun testo «N provati» in quel caso. Una sezione senza
    il numero dei provati (`{}`, `{selectors_found: []}`) non dice nulla. Una sezione senza la lista dei non
    determinati (`{tested, active}`, DKIM senza `selectors_unknown`) si legge come le sole liste dei trovati, senza
    «nessuno»: in quella forma una sezione senza nomi può essere anche un DNS senza risposta;
  * report: con un sottodominio o un selettore non determinato o riportato lo stato del DNS non comincia per «ok»;
  * il marcatore si legge per nome, preso dalle liste, con voce propria (`hasOwnProperty`): le sue chiavi non
    producono righe né marche, e i nomi `constructor`, `__proto__`, `toString`, `hasOwnProperty` sono nomi come gli
    altri. Nessuna copia del marcatore (`Object.assign`, `for…in`): una chiave `__proto__` cambierebbe il prototipo.
    Una voce vale solo se è un oggetto con `carried_at` stringa non vuota, e solo per un nome stringa;
  * valori ostili (nomi, chiavi, date, numeri dei provati) escono come testo, mai come elementi o attributi; campi
    del riporto per nome malformati (liste che non sono liste, voci che non sono stringhe, marcatore che non è un
    oggetto, numeri al posto di stringhe e viceversa) non fanno sollevare la resa; una voce `null` in `active` non fa
    sollevare il report;
  * il costo cresce con la lunghezza delle liste, non con il suo quadrato: si contano gli elementi che i metodi di
    `Array.prototype` scorrono durante una resa (nessuna misura di tempo).

La lingua dei testi segue le note di riporto della pagina («riportata dal ciclo precedente», «data ignota», «tipi
non determinati»). Il testo esatto non è fissato oltre le parole chiave sopra.

Come `tests/test_dashboard_render.py`: lo script vero di `services/dashboard_app.html` gira in un contesto `vm` di
node (`tests/dashboard_render.js`, un solo processo per modulo) e si legge l'HTML prodotto con `html.parser`. Una
parte degli snapshot è prodotta dal codice vero del riporto (`_persist_intel`, con store e `/diff` finti, come in
`tests/test_dns_carry_over_col31.py`). Il conteggio del costo gira in un secondo contesto `vm`, con `node -e` e lo
script di `_COST_JS`. Senza node i test si saltano, salvo `DOMAINSENTRY_REQUIRE_NODE=1`.
I test segnati «controllo» fissano ciò che non deve cambiare. Valori di prova: indirizzi RFC 5737, nomi RFC 2606.
"""
import copy
import importlib
import json
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from pathlib import Path

import pytest

import test_dns_carry_over_col31 as _col31        # zona sana, tagli e `_persist` del riporto per nome
from shared.constants import DEFAULT_DKIM_SELECTORS, DEFAULT_SUBDOMAINS

_HARNESS = Path(__file__).with_name("dashboard_render.js")
_PAGE = Path(__file__).parent.parent / "services" / "dashboard_app.html"
_TIMEOUT_S = 60

_DOMAIN = "acme-typo.example"
_T0 = "2026-10-20T10:00:00+00:00"            # ultima osservazione reale
_NOW = "2026-10-21T10:00:30+00:00"           # ciclo che riporta
_DAY = "2026-10-20"
_CYCLE = "2026-11-05T10:00:30+00:00"         # ciclo di un guasto, lontano dall'ultima osservazione
_CYCLE_DAY = "2026-11-05"
_UNSET = object()                              # nel marcatore: «la chiave observed_at non c'è»
_HOSTILE_DATE = '<zz>"\'&amp;<zz>'            # un tag intero entro i primi 10 caratteri
_INJECTED_ATTRIBUTES = {"onerror", "onload", "onmouseover"}
_RAW_MARKUP = ("<img src=x", "<svg onload", "<b id=x74", "<zz>")


def _sub(label):
    return f"{label}.{_DOMAIN}"


_ALL_SUBS = [_sub(s) for s in DEFAULT_SUBDOMAINS]
_WWW, _MAIL, _LOGIN, _VPN, _API, _ADMIN = (_sub(s) for s in ("www", "mail", "login", "vpn", "api", "admin"))
_PROTO_NAMES = ("constructor", "__proto__", "toString", "hasOwnProperty", "valueOf")


def _active(fqdn, ip="192.0.2.20"):
    return {"fqdn": fqdn, "A": [ip], "CNAME": []}


def _entry(observed=_T0, carried=_NOW):
    entry = {"carried_at": carried}
    if observed is not _UNSET:
        entry["observed_at"] = observed
    return entry


def _subs(active=(), unknown=(), marker=None, tested=25):
    section = {"tested": tested, "active": [copy.deepcopy(a) for a in active], "unknown": list(unknown)}
    if marker is not None:
        section["carried_over"] = copy.deepcopy(marker)
    return section


def _dkim(found=(), unknown=(), marker=None, tested=18):
    section = {"selectors_found": list(found), "selectors_tested": tested,
               "records": {s: [f'"v=DKIM1; k=rsa; p={s}"'] for s in found if isinstance(s, str)},
               "selectors_unknown": list(unknown)}
    if marker is not None:
        section["carried_over"] = copy.deepcopy(marker)
    return section


def _intel(subdomains=_UNSET, dkim=_UNSET, dns=_UNSET):
    """Intel di un dominio con tutti i moduli riusciti. `subdomains` e `dkim` sostituiscono le due sezioni
    (`_UNSET`: quelle di uno snapshot senza dati, `{}` e `{selectors_found: []}`); `dns` l'intera sezione."""
    section = {
        "domain": _DOMAIN, "timestamp": _T0,
        "records": {"A": ["192.0.2.10"], "AAAA": [], "MX": [f"10 mail.{_DOMAIN}"], "NS": [], "TXT": [], "SOA": [],
                    "CNAME": []},
        "records_status": {"A": "ok", "AAAA": "nodata", "MX": "ok", "NS": "nodata", "TXT": "nodata",
                           "SOA": "nodata", "CNAME": "nodata"},
        "email_auth": {"dkim": {"selectors_found": []}},
        "subdomains": {}, "error": None}
    if subdomains is not _UNSET:
        section["subdomains"] = copy.deepcopy(subdomains)
    if dkim is not _UNSET:
        section["email_auth"]["dkim"] = copy.deepcopy(dkim)
    return {
        "dns": section if dns is _UNSET else copy.deepcopy(dns),
        "cert": {"domain": _DOMAIN, "timestamp": _T0, "error": None,
                 "ct_certificates": {"total": 21, "certificates": [
                     {"id": 1, "common_name": _DOMAIN, "issuer_name": "Example CA"}]}},
        "whois": {"domain": _DOMAIN, "timestamp": _T0, "registrar": "Registrar Example",
                  "creation_date": "2020-01-01T00:00:00", "error": None},
        "http": {"domain": _DOMAIN, "timestamp": _T0, "overall_status": "active", "error": None,
                 "checks": [{"url": f"http://{_DOMAIN}", "status_code": 200, "title": "Acme",
                             "content_length": 5400, "server": "nginx", "error": None}]},
        "reputation": {"domain": _DOMAIN, "timestamp": _T0, "risk_score": 0, "risk_level": "clean", "error": None},
    }


_CASES = {}


def _add(name, intel):
    assert name not in _CASES, name
    _CASES[name] = intel


# ── Snapshot di prova: i tre stati ─────────────────────────────────────────────────────────────────────────

_add("plain", _intel())
_add("sub_none", _intel(subdomains=_subs()))
_add("sub_all_undetermined", _intel(subdomains=_subs(unknown=_ALL_SUBS)))
_add("dkim_none", _intel(dkim=_dkim()))
_add("dkim_all_undetermined", _intel(dkim=_dkim(unknown=DEFAULT_DKIM_SELECTORS)))
_add("sub_none_dkim_all_undetermined", _intel(subdomains=_subs(), dkim=_dkim(unknown=DEFAULT_DKIM_SELECTORS)))
_add("sub_all_undetermined_dkim_none", _intel(subdomains=_subs(unknown=_ALL_SUBS), dkim=_dkim()))

# Miscugli
_add("sub_some_undetermined", _intel(subdomains=_subs(active=[_active(_WWW), _active(_MAIL, "192.0.2.21")],
                                                      unknown=[_VPN, _API])))
_add("dkim_some_undetermined", _intel(dkim=_dkim(found=["google"], unknown=["k1", "k2"])))

# Dati completi, e le sole liste dei trovati
_COMPLETE_SUBS = [_active(_WWW), _active(_MAIL, "192.0.2.21"),
                  {"fqdn": _sub("autodiscover"), "A": [], "CNAME": ["autodiscover.provider.example"]}]
_add("sub_complete", _intel(subdomains=_subs(active=_COMPLETE_SUBS)))
_add("sub_found_list_only", _intel(subdomains={"active": copy.deepcopy(_COMPLETE_SUBS)}))
_add("dkim_complete", _intel(dkim=_dkim(found=["google", "selector1"])))
_add("dkim_found_list_only", _intel(dkim={"selectors_found": ["google", "selector1"]}))
_add("both_complete", _intel(subdomains=_subs(active=_COMPLETE_SUBS), dkim=_dkim(found=["google", "selector1"])))
_add("both_found_lists_only", _intel(subdomains={"active": copy.deepcopy(_COMPLETE_SUBS)},
                                     dkim={"selectors_found": ["google", "selector1"]}))

# Riportati
_add("sub_carried", _intel(subdomains=_subs(active=[_active(_WWW), _active(_LOGIN, "192.0.2.30")],
                                            unknown=[_LOGIN, _VPN], marker={_LOGIN: _entry()})))
_add("dkim_carried", _intel(dkim=_dkim(found=["google", "selector1"], unknown=["selector1", "k1"],
                                       marker={"selector1": _entry()})))
# Percorso del guasto totale: i nomi della sezione precedente, tutti marcati, `unknown` vuoto.
_add("sub_carried_only", _intel(subdomains=_subs(active=[_active(_WWW), _active(_LOGIN, "192.0.2.30")],
                                                 marker={_WWW: _entry(), _LOGIN: _entry()})))
_add("dkim_carried_only", _intel(dkim=_dkim(found=["google", "selector1"],
                                            marker={"google": _entry(), "selector1": _entry()})))
# Un nome in `active` e in `unknown` senza voce nel marcatore: si conta una volta, senza marca.
_add("sub_active_and_unknown_unmarked", _intel(subdomains=_subs(active=[_active(_WWW)], unknown=[_WWW, _VPN])))
_add("dkim_found_and_unknown_unmarked", _intel(dkim=_dkim(found=["google"], unknown=["google", "k1"])))

# observed_at che non è una data, vuoto, lunghissimo, ostile
_NOT_A_DATE = {
    "null": None, "missing": _UNSET, "empty": "", "number": 5, "huge-number": 1e21, "zero": 0, "true": True,
    "false": False, "array": [_T0], "empty-array": [], "object": {"a": _T0}, "own-tostring": {"toString": 1},
    "own-valueof": {"valueOf": "x", "toString": "y"},
}
for _kind, _value in _NOT_A_DATE.items():
    _add(f"date_{_kind}", _intel(
        subdomains=_subs(active=[_active(_WWW), _active(_LOGIN)], unknown=[_LOGIN], marker={_LOGIN: _entry(_value)}),
        dkim=_dkim(found=["google", "selector1"], unknown=["selector1"], marker={"selector1": _entry(_value)})))
_LONG_DATE = _T0 + "Q" * 5000
_add("date_long", _intel(
    subdomains=_subs(active=[_active(_WWW), _active(_LOGIN)], unknown=[_LOGIN], marker={_LOGIN: _entry(_LONG_DATE)}),
    dkim=_dkim(found=["google", "selector1"], unknown=["selector1"], marker={"selector1": _entry(_LONG_DATE)})))
_add("date_hostile", _intel(
    subdomains=_subs(active=[_active(_WWW), _active(_LOGIN)], unknown=[_LOGIN],
                     marker={_LOGIN: _entry(_HOSTILE_DATE)}),
    dkim=_dkim(found=["google", "selector1"], unknown=["selector1"], marker={"selector1": _entry(_HOSTILE_DATE)})))

# «Nessuno» con la data della sezione (`dns.timestamp`)

def _none_with_timestamp(value):
    intel = _intel(subdomains=_subs(), dkim=_dkim())
    if value is _UNSET:
        del intel["dns"]["timestamp"]
    else:
        intel["dns"]["timestamp"] = value
    return intel


for _kind, _value in _NOT_A_DATE.items():
    _add(f"none_timestamp_{_kind}", _none_with_timestamp(_value))
_add("none_timestamp_long", _none_with_timestamp(_LONG_DATE))
_add("none_timestamp_hostile", _none_with_timestamp(_HOSTILE_DATE))
_add("none_timestamp_markup", _none_with_timestamp('"><img src=x onerror=probe74(8)>'))

# Sezioni senza la lista dei non determinati: senza nomi possono essere anche un DNS senza risposta.
_add("no_unknown_list_none", _intel(subdomains={"tested": 25, "active": []},
                                    dkim={"selectors_found": [], "selectors_tested": 18, "records": {}}))
_add("no_unknown_list_found", _intel(
    subdomains={"tested": 25, "active": copy.deepcopy(_COMPLETE_SUBS)},
    dkim={"selectors_found": ["google", "selector1"], "selectors_tested": 18,
          "records": {"google": ['"v=DKIM1; k=rsa; p=google"'], "selector1": ['"v=DKIM1; k=rsa; p=selector1"']}}))

# ── Lettura del marcatore ──────────────────────────────────────────────────────────────────────────────────

_GHOSTS = (_ADMIN, "x74-ghost-key", "<b id=x74-ghost>")
_add("marker_keys_not_in_the_lists", _intel(
    subdomains=_subs(active=[_active(_WWW)], unknown=[_VPN], marker={g: _entry() for g in _GHOSTS}),
    dkim=_dkim(found=["google"], unknown=["k1"], marker={g: _entry() for g in ("selector2", *_GHOSTS[1:])})))
_PROTO_ACTIVE = [_active(n, f"192.0.2.{40 + i}") for i, n in enumerate(_PROTO_NAMES)]
_add("proto_names_without_own_entry", _intel(
    subdomains=_subs(active=_PROTO_ACTIVE, marker={_ADMIN: _entry()}),
    dkim=_dkim(found=list(_PROTO_NAMES), marker={"selector2": _entry()})))
_OWN = ("__proto__", "hasOwnProperty")         # voce propria; `constructor`, `toString`, `valueOf` no
_add("proto_names_with_own_entry", _intel(
    subdomains=_subs(active=_PROTO_ACTIVE, marker={n: _entry() for n in _OWN}),
    dkim=_dkim(found=list(_PROTO_NAMES), marker={n: _entry() for n in _OWN})))
# `__proto__` come CHIAVE del marcatore: dopo `JSON.parse` è una chiave propria. Copiata con `Object.assign` o
# `for…in` diventerebbe il prototipo della copia, e `www.` si leggerebbe riportato attraverso la catena.
_add("proto_key_holding_other_names", _intel(
    subdomains=_subs(active=[_active(_WWW)], marker={"__proto__": {_WWW: _entry()}}),
    dkim=_dkim(found=["google"], marker={"__proto__": {"google": _entry()}})))

# ── Valori ostili ──────────────────────────────────────────────────────────────────────────────────────────

_LONG_NAME = "x74-" + "L" * 5000 + f".{_DOMAIN}"
_HOSTILE_NAMES = ("<img src=x onerror=probe74(1)>", '"><svg onload=probe74(2)>', "' onmouseover='probe74(3)",
                  '" onmouseover="probe74(4)', "</td></tr><b id=x74-break>", "&lt;b id=x74-entity&gt;",
                  _LONG_NAME, "__proto__", "constructor")
_add("hostile_names", _intel(
    subdomains=_subs(active=[_active(_WWW)], unknown=list(_HOSTILE_NAMES),
                     marker={n: _entry(_HOSTILE_DATE) for n in _HOSTILE_NAMES}),
    dkim=_dkim(found=["google"], unknown=list(_HOSTILE_NAMES),
               marker={n: _entry(_HOSTILE_DATE) for n in _HOSTILE_NAMES})))
_add("hostile_tested", _intel(subdomains=_subs(tested="<b id=x74-tested>"),
                              dkim=_dkim(tested="<b id=x74-selectors-tested>")))
# Nomi ostili TROVATI e riportati: escono come testo, con la loro marca.
_add("hostile_names_carried", _intel(
    subdomains=_subs(active=[_active(n) for n in _HOSTILE_NAMES[:5]], unknown=list(_HOSTILE_NAMES[:5]),
                     marker={n: _entry() for n in _HOSTILE_NAMES[:5]}),
    dkim=_dkim(found=list(_HOSTILE_NAMES[:5]), unknown=list(_HOSTILE_NAMES[:5]),
               marker={n: _entry() for n in _HOSTILE_NAMES[:5]})))

# ── Campi del riporto per nome malformati ──────────────────────────────────────────────────────────────────
# Forme che la resa delle sole liste dei trovati non fa sollevare: i campi letti per la distinzione non devono
# aggiungere eccezioni. Le forme di `active` e di `selectors_found` che fanno sollevare anche quella resa sono fuori
# da questo contratto.

_NOT_A_LIST = {"string": "vpn", "number": 5, "null": None, "true": True, "object": {"length": 2, "0": _VPN},
               "empty-object": {}, "own-tostring": {"toString": 1}}
# Una `length` vera senza `map`/`join` (stringa, oggetto con `length`) è una di quelle forme.
_NOT_A_FOUND_LIST = {k: v for k, v in _NOT_A_LIST.items() if k not in ("string", "object")}
_BAD_ITEMS = [None, 5, 1e21, True, {}, {"toString": 1}, [_VPN], ["x"], _VPN, "k1"]
_NOT_A_MARKER = {"string": "carried", "array": [_LOGIN, "selector1"], "number": 5, "null": None, "true": True,
                 "entry-string": "x", "entry-null": None, "entry-array": [], "entry-number": 5,
                 "entry-without-carried-at": {"observed_at": _T0},
                 "entry-true": True, "carried-at-own-tostring": {"observed_at": _T0, "carried_at": {"toString": 1}},
                 "carried-at-number": {"observed_at": _T0, "carried_at": 5},
                 "carried-at-empty": {"observed_at": _T0, "carried_at": ""},
                 "carried-at-true": {"observed_at": _T0, "carried_at": True},
                 "carried-at-object": {"observed_at": _T0, "carried_at": {"at": _NOW}},
                 "carried-at-array": {"observed_at": _T0, "carried_at": [_NOW]}}
_NOT_A_COUNT = {"string": "25", "own-tostring": {"toString": 1}, "object": {}, "array": [25], "null": None,
                "negative": -1, "huge": 1e21, "true": True}
_MALFORMED = {}


def _malformed(name, intel):
    _MALFORMED[name] = intel
    _add(f"malformed_{name}", intel)


for _kind, _value in _NOT_A_LIST.items():
    _malformed(f"sub_unknown_{_kind}", _intel(subdomains={**_subs(active=[_active(_WWW)]), "unknown": _value}))
    _malformed(f"sub_unknown_{_kind}_nothing_active", _intel(subdomains={**_subs(), "unknown": _value}))
    _malformed(f"dkim_unknown_{_kind}", _intel(dkim={**_dkim(found=["google"]), "selectors_unknown": _value}))
    _malformed(f"dkim_unknown_{_kind}_nothing_found", _intel(dkim={**_dkim(), "selectors_unknown": _value}))
for _kind, _value in _NOT_A_FOUND_LIST.items():
    _malformed(f"sub_active_{_kind}", _intel(subdomains={**_subs(unknown=[_VPN]), "active": _value}))
    _malformed(f"dkim_found_{_kind}", _intel(dkim={**_dkim(unknown=["k1"]), "selectors_found": _value}))
_malformed("sub_unknown_bad_items", _intel(subdomains=_subs(active=[_active(_WWW)], unknown=_BAD_ITEMS)))
_malformed("dkim_unknown_bad_items", _intel(dkim=_dkim(found=["google"], unknown=_BAD_ITEMS)))
_malformed("dkim_found_bad_items", _intel(dkim=_dkim(found=[None, 5, "google"], unknown=["google", "k1"],
                                                     marker={"google": _entry()})))
_malformed("sub_active_fqdn_not_a_string", _intel(subdomains=_subs(
    active=[{"fqdn": 5, "A": ["192.0.2.20"], "CNAME": []}, {"A": ["192.0.2.21"]}, _active(_WWW)],
    unknown=[_WWW, _VPN], marker={"5": _entry(), _WWW: _entry()})))
# Un nome che non è una stringa, con una voce valida sotto la sua forma di testo («5»).
_add("name_not_a_string", _intel(
    subdomains=_subs(active=[{"fqdn": 5, "A": ["192.0.2.25"], "CNAME": []}, _active(_WWW)], marker={"5": _entry()}),
    dkim=_dkim(found=[5, "google"], marker={"5": _entry()})))
# Una voce `null` in `active` fa sollevare la scheda Intel anche con le sole liste dei trovati (fuori da questo
# contratto); il report, che di `active` legge solo i nomi, non deve sollevare.
_REPORT_ONLY = ("report_active_null_entry", "report_active_only_null")
_add("report_active_null_entry", _intel(subdomains=_subs(active=[None, _active(_WWW)], unknown=[_WWW, _VPN],
                                                         marker={_WWW: _entry()})))
_add("report_active_only_null", _intel(subdomains=_subs(active=[None])))
for _kind, _value in _NOT_A_MARKER.items():
    _marker = {_LOGIN: _value} if _kind.startswith(("entry-", "carried-at-")) else _value
    _dkim_marker = {"selector1": _value} if _kind.startswith(("entry-", "carried-at-")) else _value
    _malformed(f"marker_{_kind}", _intel(
        subdomains={**_subs(active=[_active(_WWW), _active(_LOGIN)], unknown=[_LOGIN]), "carried_over": _marker},
        dkim={**_dkim(found=["google", "selector1"], unknown=["selector1"]), "carried_over": _dkim_marker}))
for _kind, _value in _NOT_A_COUNT.items():
    _malformed(f"tested_{_kind}", _intel(subdomains=_subs(tested=_value), dkim=_dkim(tested=_value)))
for _kind, _value in {"string": "x", "array": [], "number": 5, "null": None, "true": True}.items():
    _malformed(f"sub_section_{_kind}", _intel(subdomains=_value, dkim=_dkim(unknown=["k1"])))
    _malformed(f"dkim_section_{_kind}", _intel(subdomains=_subs(unknown=[_VPN]), dkim=_value))
    _malformed(f"email_auth_{_kind}", {**_intel(subdomains=_subs(unknown=[_VPN])),
                                       "dns": {**_intel(subdomains=_subs(unknown=[_VPN]))["dns"], "email_auth": _value}})


# ── Lettura della resa come la legge un browser ────────────────────────────────────────────────────────────

_VOID = frozenset({"meta", "input", "br", "hr", "img", "link"})


class _Node:
    def __init__(self, tag, attrs, parent):
        self.tag, self.attrs, self.parent, self.children = tag, list(attrs), parent, []

    def descendants(self):
        for child in self.children:
            if not isinstance(child, str):
                yield child
                yield from child.descendants()

    def classes(self):
        return (dict(self.attrs).get("class") or "").split()

    def strings(self):
        for child in self.children:
            if isinstance(child, str):
                yield child
            else:
                yield from child.strings()

    def text(self):
        """Il testo, con uno spazio fra un nodo di testo e il seguente (fra due celle, per esempio)."""
        return " ".join(" ".join(self.strings()).split())


class _Builder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = self.current = _Node("#document", [], None)

    def handle_starttag(self, tag, attrs):
        node = _Node(tag, attrs, self.current)
        self.current.children.append(node)
        if tag not in _VOID:
            self.current = node

    def handle_startendtag(self, tag, attrs):
        self.current.children.append(_Node(tag, attrs, self.current))

    def handle_endtag(self, tag):
        node = self.current
        while node is not self.root and node.tag != tag:
            node = node.parent
        if node is not self.root:
            self.current = node.parent

    def handle_data(self, data):
        self.current.children.append(data)


def _parse(markup):
    builder = _Builder()
    builder.feed(markup)
    builder.close()
    return builder.root


def _cells(row):
    return [c for c in row.children if not isinstance(c, str) and c.tag in ("td", "th")]


def _token(name):
    """Il nome come parola intera: `mail.` non si trova dentro `webmail.`, né `k1` dentro `everlytickey1`."""
    return re.compile(r"(?<![\w.-])" + re.escape(name) + r"(?![\w.-])")


def _first_number_after(word, text):
    match = re.search(re.escape(word) + r"\w*\D{0,80}?(\d+)", text)
    return int(match.group(1)) if match else None


class _Tab:
    """La scheda Intel, blocco DNS."""

    def __init__(self, markup):
        self.markup = markup
        self.tree = _parse(markup)
        sections = [n for n in self.tree.descendants() if n.tag == "div" and "intel-sec" in n.classes()
                    and dict(n.attrs).get("data-sec") == "dns"]
        assert len(sections) == 1, "la scheda Intel non ha un blocco DNS"
        self.dns = sections[0]

    def rows(self, first_cell):
        """Il testo delle celle dopo la prima, per ogni riga del blocco DNS la cui prima cella è `first_cell`."""
        out = []
        for row in (n for n in self.dns.descendants() if n.tag == "tr"):
            cells = _cells(row)
            if cells and cells[0].text() == first_cell:
                out.append(" ".join(c.text() for c in cells[1:]))
        return out

    def row(self, first_cell):
        rows = self.rows(first_cell)
        assert len(rows) == 1, f"righe con prima cella {first_cell!r}: {rows}"
        return rows[0]

    def dkim(self):
        """Il testo delle righe DKIM, unito."""
        return " | ".join(self.rows("DKIM"))

    def subdomains(self):
        """Il testo del blocco dei sottodomini, dal titolo «Subdomains…» alla fine del blocco DNS; None se manca."""
        texts, inside = [], False
        stack = list(reversed(self.dns.children))
        while stack:
            node = stack.pop()
            if isinstance(node, str):
                if inside:
                    texts.append(node)
                continue
            if not inside and "block-title" in node.classes() and node.text().startswith("Subdomains"):
                inside = True
            stack.extend(reversed(node.children))
        return " ".join(" ".join(texts).split()) if inside else None

    def subdomain_text(self):
        text = self.subdomains()
        assert text is not None, "il blocco dei sottodomini non c'è"
        return text

    def segments(self, names):
        """{nome: testo dopo il nome fino al nome seguente della stessa riga DKIM, o alla fine della riga}. Ogni
        nome compare una volta nelle righe DKIM."""
        rows = self.rows("DKIM")
        out = {}
        for name in names:
            hits = [(row, m) for row in rows for m in _token(name).finditer(row)]
            assert len(hits) == 1, f"{name!r} compare {len(hits)} volte nelle righe DKIM: {rows}"
            row, hit = hits[0]
            following = [m.start() for other in names if other != name for m in _token(other).finditer(row)
                         if m.start() >= hit.end()]
            out[name] = row[hit.end():min(following, default=len(row))]
        return out

    def from_the_data(self):
        """Ciò che i valori ostili producono se escono dal testo: un elemento `zz`, un id `x74-…`, un attributo
        `onerror`/`onload`/`onmouseover`, o il loro markup grezzo. La pagina usa `<b>` e `<svg>` per conto suo:
        quei tag non bastano a dire che un valore è diventato markup."""
        found = [f"<{n.tag}>" for n in self.tree.descendants() if n.tag == "zz"]
        found += [f"<{n.tag} {name}={value}>" for n in self.tree.descendants() for name, value in n.attrs
                  if name in _INJECTED_ATTRIBUTES or (name == "id" and (value or "").startswith("x74"))]
        return found + [raw for raw in _RAW_MARKUP if raw in self.markup]


def _dns_status(report_markup):
    """Lo stato del DNS nella riga «Module status» del report («DNS ok · WHOIS ok · …»)."""
    tree = _parse(report_markup)
    for row in (n for n in tree.descendants() if n.tag == "tr"):
        cells = _cells(row)
        if len(cells) >= 2 and cells[0].text() == "Module status":
            first = cells[1].text().split("·")[0].strip()
            assert first.startswith("DNS "), first
            return first[len("DNS "):]
    raise AssertionError("il report non ha la riga Module status")


class _Rendered:
    def __init__(self, result):
        self.result = result

    def raw(self, name):
        assert self.result["load_error"] is None, f"lo script della dashboard non si carica: {self.result['load_error']}"
        case = self.result["cases"][name]
        assert case["error"] is None, f"la resa di '{name}' ha sollevato: {case['error']}"
        return case

    def tab(self, name):
        return _Tab(self.raw(name)["intel_tab"])

    def report(self, name):
        """Il report di `name`, che deve essere reso anche se la scheda Intel ha sollevato."""
        assert self.result["load_error"] is None, f"lo script della dashboard non si carica: {self.result['load_error']}"
        case = self.result["cases"][name]
        assert case["report"] is not None and "buildHtmlReport" not in (case["error"] or ""), \
            f"il report di '{name}' ha sollevato: {case['error']}"
        return case["report"]

    def status(self, name):
        return _dns_status(self.report(name))


# ── Snapshot prodotti dal codice vero del riporto per nome ──────────────────────────────────────────────────

def _hostile_previous():
    """La sezione precedente di una zona i cui nomi trovati (salvati da un ciclo precedente, quindi da disco) hanno
    nomi ostili o della catena dei prototipi: il guasto totale li marca tutti."""
    prev = _col31._healthy()
    prev["subdomains"]["active"] += [_active(n, f"198.51.100.{60 + i}")
                                     for i, n in enumerate(("__proto__", "constructor", "toString",
                                                            "<img src=x onerror=probe74(5)>"))]
    dkim = prev["email_auth"]["dkim"]
    for i, name in enumerate(("__proto__", "constructor")):
        dkim["selectors_found"].append(name)
        dkim["records"][name] = [f'"v=DKIM1; k=rsa; p=HOSTILE{i}"']
    return prev


def _zone_without_names(timestamp=_T0):
    """`/dns` di una zona con il solo record A: nessun sottodominio attivo, nessun selettore trovato, nulla di non
    determinato."""
    dns = _col31._healthy()
    dns["timestamp"] = timestamp
    dns["records"] = {t: (["192.0.2.10"] if t == "A" else []) for t in _col31._BASE}
    dns["records_status"] = {t: ("ok" if t == "A" else "nodata") for t in _col31._BASE}
    for section in ("spf", "dmarc", "bimi", "caa"):
        dns["email_auth"][section] = {"present": False, "records": [], "status": "nodata"}
    dns["email_auth"]["dkim"].update(selectors_found=[], records={})
    dns["subdomains"]["active"] = []
    return dns


def _without_selectors():
    dns = _col31._healthy()
    dns["email_auth"]["dkim"].update(selectors_found=[], records={})
    return dns


def _col31_cases():
    """{nome: sezione `dns` salvata da `_persist_intel`} per i cicli che la vista deve leggere. Store, `/diff` e
    orologio finti (`_col31._persist`); la sezione passa da JSON come dallo store."""
    orchestrator = importlib.import_module("services.orchestrator")
    healthy, cut, total, now = _col31._healthy, _col31._cut, _col31._total_failure, _col31._NOW
    cycles = {
        "col31_partial": (healthy(), cut(healthy(), subdomains=[_col31._LOGIN, _sub("vpn")],
                                         selectors=["selector1", "k1"]), True, now),
        "col31_stage_cut": (healthy(), cut(healthy(), subdomains=_ALL_SUBS, selectors=DEFAULT_DKIM_SELECTORS), True,
                            now),
        "col31_total_failure": (healthy(), total(), True, now),
        "col31_section_none": (healthy(), None, True, now),
        "col31_healthy": (healthy(), healthy(), True, now),
        "col31_first_cycle_cut": (None, cut(healthy(), subdomains=_ALL_SUBS, selectors=DEFAULT_DKIM_SELECTORS),
                                  False, now),
        "col31_hostile_names_total_failure": (_hostile_previous(), total(), True, now),
        # Un precedente senza nomi, poi un guasto: la sezione salvata è quella del precedente, senza marcatori di nome.
        "col31_none_kept_total_failure": (_zone_without_names(), total(), True, _CYCLE),
        "col31_none_kept_section_none": (_zone_without_names(), None, True, _CYCLE),
        "col31_none_kept_mixed": (_without_selectors(), None, True, _CYCLE),
        "col31_fresh_none": (_zone_without_names(), _zone_without_names(_CYCLE_DAY + "T10:00:00+00:00"), True,
                             _CYCLE),
    }
    out = {}
    for name, (prev, curr, has_snapshot, cycle_now) in cycles.items():
        with pytest.MonkeyPatch.context() as mp:
            saved, _, _ = _col31._persist(mp, orchestrator, prev, curr, snapshot=has_snapshot, now=cycle_now)
        out[name] = json.loads(json.dumps(saved))
    return out


@pytest.fixture(scope="module")
def col31_dns():
    return _col31_cases()


def _node():
    node = shutil.which("node")
    if node is None:
        if os.environ.get("DOMAINSENTRY_REQUIRE_NODE") == "1":
            pytest.fail("node non disponibile ma DOMAINSENTRY_REQUIRE_NODE=1 lo richiede: la resa della dashboard "
                        "non è stata eseguita", pytrace=False)
        pytest.skip("node non disponibile: la resa della dashboard non si può eseguire")
    return node


def _run_node(args, payload, what):
    try:
        proc = subprocess.run(args, input=json.dumps(payload), capture_output=True, encoding="utf-8",
                              timeout=_TIMEOUT_S, check=False)
    except subprocess.TimeoutExpired:
        proc = None
    if proc is None:
        pytest.fail(f"{what} non ha terminato entro {_TIMEOUT_S} s: la resa della dashboard è bloccata", pytrace=False)
    if proc.returncode != 0:
        pytest.fail(f"{what} è terminato con codice {proc.returncode}: {proc.stderr[-800:]}", pytrace=False)
    return json.loads(proc.stdout)


@pytest.fixture(scope="module")
def rendered(col31_dns):
    """Un solo processo node per modulo: i casi di `_CASES` e quelli prodotti dal riporto vero, nello script vero
    della dashboard."""
    node = _node()
    cases = dict(_CASES)
    for name, dns in col31_dns.items():
        cases[name] = _intel(dns=dns)
        # Lo stesso snapshot con le sole liste dei trovati, senza marcatori: la resa delle sole liste.
        found_only = copy.deepcopy(dns)
        found_only["subdomains"] = {"active": found_only["subdomains"]["active"]}
        found_only["email_auth"]["dkim"] = {"selectors_found": found_only["email_auth"]["dkim"]["selectors_found"]}
        cases[f"{name}__found_lists_only"] = _intel(dns=found_only)
    payload = {"cases": [
        {"name": name, "domain": _DOMAIN, "client": "tenant-x", "updated_at": _NOW, "intel": intel, "history": []}
        for name, intel in cases.items()]}
    return _Rendered(_run_node([node, str(_HARNESS)], payload, _HARNESS.name))


# ── 1. Nessuno, non determinato, sezione senza dati ────────────────────────────────────────────────────────

_SIDES = {
    "subdomains": ("sub_none", "sub_all_undetermined", 25, len(_ALL_SUBS)),
    "dkim": ("dkim_none", "dkim_all_undetermined", 18, len(DEFAULT_DKIM_SELECTORS)),
}


def _side_text(tab, side):
    if side == "subdomains":
        return tab.subdomain_text()
    text = tab.dkim()
    assert text, "nessuna riga DKIM"
    return text


class TestNoneAndUndeterminedAreTwoDifferentThings:
    @pytest.mark.parametrize("side", _SIDES)
    def test_none_undetermined_and_no_data_render_three_different_intel_tabs(self, rendered, side):
        none, undetermined, _, _ = _SIDES[side]
        tabs = {name: rendered.raw(name)["intel_tab"] for name in (none, undetermined, "plain")}

        assert len(set(tabs.values())) == 3, "due dei tre stati hanno la stessa scheda Intel"

    @pytest.mark.parametrize("side", _SIDES)
    def test_none_says_nessun_with_the_number_of_names_tested(self, rendered, side):
        none, _, tested, _ = _SIDES[side]
        text = _side_text(rendered.tab(none), side)

        assert _first_number_after("nessun", text) == tested, text
        assert "non determinat" not in text

    @pytest.mark.parametrize("side", _SIDES)
    def test_all_undetermined_says_non_determinati_with_the_count_and_every_name(self, rendered, side):
        _, undetermined, _, count = _SIDES[side]
        text = _side_text(rendered.tab(undetermined), side)
        names = _ALL_SUBS if side == "subdomains" else DEFAULT_DKIM_SELECTORS

        assert _first_number_after("non determinat", text) == count, text
        assert [n for n in names if len(_token(n).findall(text)) != 1] == [], "ogni nome, una volta"
        assert "nessun" not in text

    @pytest.mark.parametrize("name, sub_word, dkim_word", [
        ("sub_none_dkim_all_undetermined", "nessun", "non determinat"),
        ("sub_all_undetermined_dkim_none", "non determinat", "nessun"),
    ])
    def test_each_side_says_its_own_state(self, rendered, name, sub_word, dkim_word):
        tab = rendered.tab(name)
        other = {"nessun": "non determinat", "non determinat": "nessun"}

        assert sub_word in tab.subdomain_text() and other[sub_word] not in tab.subdomain_text()
        assert dkim_word in tab.dkim() and other[dkim_word] not in tab.dkim()

    def test_control_a_section_without_the_number_tested_says_nothing(self, rendered):
        # Controllo: `subdomains: {}` e `dkim: {selectors_found: []}`, la forma di uno snapshot senza dati.
        tab = rendered.tab("plain")

        assert tab.subdomains() is None
        assert tab.rows("DKIM") == []


def _none_line(tab, side):
    """La riga «nessun…» di `side`: la riga DKIM che lo dice, o il testo del blocco dei sottodomini da «nessun»."""
    if side == "dkim":
        lines = [row for row in tab.rows("DKIM") if "nessun" in row]
        assert len(lines) == 1, f"righe DKIM con «nessun»: {tab.rows('DKIM')}"
        return lines[0]
    text = tab.subdomain_text()
    assert "nessun" in text, text
    return text[text.index("nessun"):]


def _observed(line):
    """Ciò che la riga «nessun…» dice dopo «osserva…»: la data della sezione."""
    match = re.search(r"osserva\w*", line)
    assert match, f"la riga «nessun…» non dice quando la sezione è stata osservata: {line!r}"
    return line[match.end():]


class TestNoneSaysWhenTheSectionWasObserved:
    """«Nessuno» è un'osservazione della sezione: la riga porta la sua data (`dns.timestamp`). Nel guasto totale la
    sezione salvata è quella del precedente, e la data è quella; i casi del riporto vero sono nella sezione 8."""

    @pytest.mark.parametrize("side", _SIDES)
    def test_the_none_line_shows_the_day_after_the_number_tested(self, rendered, side):
        none, _, tested, _ = _SIDES[side]
        line = _none_line(rendered.tab(none), side)

        assert _first_number_after("nessun", line) == tested, line
        assert _DAY in _observed(line), line

    @pytest.mark.parametrize("side", _SIDES)
    @pytest.mark.parametrize("kind", _NOT_A_DATE)
    def test_a_timestamp_that_is_not_a_date_says_data_ignota(self, rendered, side, kind):
        line = _none_line(rendered.tab(f"none_timestamp_{kind}"), side)

        assert "data ignota" in _observed(line), line

    def test_a_very_long_timestamp_is_cut(self, rendered):
        tab = rendered.tab("none_timestamp_long")

        assert "Q" * 64 not in tab.markup
        assert [side for side in _SIDES if _DAY not in _observed(_none_line(tab, side))] == []

    @pytest.mark.parametrize("name", ["none_timestamp_hostile", "none_timestamp_markup"])
    def test_a_hostile_timestamp_is_text(self, rendered, name):
        tab = rendered.tab(name)

        assert tab.from_the_data() == []
        for side in _SIDES:
            assert "data ignota" not in _observed(_none_line(tab, side)), "una stringa si stampa, escapata"

    def test_the_hostile_timestamp_is_shown_as_it_is(self, rendered):
        tab = rendered.tab("none_timestamp_hostile")

        assert [side for side in _SIDES if "<zz>" not in _observed(_none_line(tab, side))] == []


class TestPartialMixes:
    def test_active_subdomains_and_undetermined_ones(self, rendered):
        tab = rendered.tab("sub_some_undetermined")
        text = tab.subdomain_text()

        assert tab.row(_WWW) == "192.0.2.20" and tab.row(_MAIL) == "192.0.2.21"
        assert _first_number_after("non determinat", text) == 2, text
        assert len(_token(_VPN).findall(text)) == 1 and len(_token(_API).findall(text)) == 1
        assert "nessun" not in text and "riportat" not in text

    def test_found_selectors_and_undetermined_ones(self, rendered):
        tab = rendered.tab("dkim_some_undetermined")
        text = tab.dkim()

        assert "riportat" not in tab.segments(["google", "k1", "k2"])["google"]
        assert _first_number_after("non determinat", text) == 2, text
        assert "nessun" not in text and "riportat" not in text


# ── 2. Riportati ───────────────────────────────────────────────────────────────────────────────────────────

class TestCarriedNamesSayRiportatoWithTheirDate:
    def test_a_carried_subdomain_row_says_riportato_with_the_day_of_the_last_observation(self, rendered):
        row = rendered.tab("sub_carried").row(_LOGIN)

        assert "192.0.2.30" in row
        assert "riportat" in row and _DAY in row, row

    def test_a_subdomain_answered_in_the_cycle_has_no_mark(self, rendered):
        row = rendered.tab("sub_carried").row(_WWW)

        assert "192.0.2.20" in row and "riportat" not in row

    def test_a_carried_selector_says_riportato_with_the_day_and_the_fresh_one_does_not(self, rendered):
        segments = rendered.tab("dkim_carried").segments(["google", "selector1", "k1"])

        assert "riportat" in segments["selector1"] and _DAY in segments["selector1"], segments
        assert "riportat" not in segments["google"], segments

    @pytest.mark.parametrize("name", ["sub_carried_only", "dkim_carried_only"])
    def test_every_carried_name_is_marked_also_with_nothing_undetermined(self, rendered, name):
        tab = rendered.tab(name)
        if name.startswith("sub"):
            marks = {n: tab.row(n) for n in (_WWW, _LOGIN)}
        else:
            marks = tab.segments(["google", "selector1"])

        assert all("riportat" in t and _DAY in t for t in marks.values()), marks
        assert "non determinat" not in (tab.subdomains() or "") + tab.dkim()

    @pytest.mark.parametrize("kind", _NOT_A_DATE)
    def test_an_observation_that_is_not_a_date_says_data_ignota(self, rendered, kind):
        tab = rendered.tab(f"date_{kind}")
        login, selector = tab.row(_LOGIN), tab.segments(["google", "selector1"])["selector1"]

        for mark in (login, selector):
            assert "riportat" in mark and "data ignota" in mark, mark
        assert "riportat" not in tab.row(_WWW)

    def test_a_very_long_date_is_cut(self, rendered):
        tab = rendered.tab("date_long")

        assert "Q" * 64 not in tab.markup
        assert _DAY in tab.row(_LOGIN) and _DAY in tab.segments(["google", "selector1"])["selector1"]

    def test_a_hostile_date_is_text(self, rendered):
        tab = rendered.tab("date_hostile")

        assert tab.from_the_data() == []
        assert "<zz>" in tab.row(_LOGIN)
        assert "<zz>" in tab.segments(["google", "selector1"])["selector1"]


class TestACarriedNameIsCountedOnce:
    """Un nome riportato è in `active` (o `selectors_found`) e in `unknown`: una riga, con la marca, e non fra i
    non determinati."""

    def test_a_carried_subdomain_appears_once_and_is_not_counted_as_undetermined(self, rendered):
        text = rendered.tab("sub_carried").subdomain_text()

        assert len(_token(_LOGIN).findall(text)) == 1, text
        assert _first_number_after("non determinat", text) == 1, text
        assert len(_token(_VPN).findall(text)) == 1

    def test_a_carried_selector_appears_once_and_is_not_counted_as_undetermined(self, rendered):
        text = rendered.tab("dkim_carried").dkim()

        assert len(_token("selector1").findall(text)) == 1, text
        assert _first_number_after("non determinat", text) == 1, text

    def test_a_name_both_found_and_unknown_without_a_mark_is_counted_once(self, rendered):
        sub, dkim = rendered.tab("sub_active_and_unknown_unmarked"), rendered.tab("dkim_found_and_unknown_unmarked")

        assert len(_token(_WWW).findall(sub.subdomain_text())) == 1 and "riportat" not in sub.row(_WWW)
        assert _first_number_after("non determinat", sub.subdomain_text()) == 1
        assert len(_token("google").findall(dkim.dkim())) == 1
        assert _first_number_after("non determinat", dkim.dkim()) == 1


# ── 3. Report ──────────────────────────────────────────────────────────────────────────────────────────────

class TestReportModuleStatus:
    @pytest.mark.parametrize("name", ["sub_all_undetermined", "sub_some_undetermined", "dkim_all_undetermined",
                                      "dkim_some_undetermined", "sub_carried", "dkim_carried", "sub_carried_only",
                                      "dkim_carried_only", "sub_none_dkim_all_undetermined"])
    def test_dns_is_not_ok_with_an_undetermined_or_carried_name(self, rendered, name):
        status = rendered.status(name)

        assert not status.startswith("ok"), f"'{name}': DNS {status}"

    @pytest.mark.parametrize("name", ["plain", "sub_none", "dkim_none", "sub_complete", "dkim_complete",
                                      "both_complete", "proto_key_holding_other_names", "proto_names_without_own_entry"])
    def test_control_dns_stays_ok_with_nothing_undetermined_or_carried(self, rendered, name):
        assert rendered.status(name) == "ok"


# ── 4. Dati completi ───────────────────────────────────────────────────────────────────────────────────────

class TestCompleteDataRendersAsTheFoundListsAlone:
    """Controllo: nulla di non determinato né di riportato. Nessun testo in più, nemmeno «N provati»."""

    @pytest.mark.parametrize("complete, found_only", [("sub_complete", "sub_found_list_only"),
                                                      ("dkim_complete", "dkim_found_list_only"),
                                                      ("both_complete", "both_found_lists_only")])
    def test_the_intel_tab_is_identical(self, rendered, complete, found_only):
        assert rendered.raw(complete)["intel_tab"] == rendered.raw(found_only)["intel_tab"]

    def test_the_found_lists_alone_render_the_title_the_rows_and_the_dkim_row(self, rendered):
        tab = rendered.tab("both_found_lists_only")
        titles = [n.text() for n in tab.dns.descendants() if "block-title" in n.classes()]

        assert titles == ["DNS records", "Subdomains (3)"]
        assert tab.row(_WWW) == "192.0.2.20" and tab.row(_MAIL) == "192.0.2.21"
        assert tab.row(_sub("autodiscover")) == "autodiscover.provider.example"
        assert tab.rows("DKIM") == ["google, selector1"]

    def test_nothing_says_nessun_non_determinato_riportato_or_provati(self, rendered):
        text = rendered.tab("both_complete").dns.text()

        for word in ("nessun", "non determinat", "riportat", "provati", "ignota"):
            assert word not in text, word


class TestSectionsWithoutTheUndeterminedListRenderAsTheFoundListsAlone:
    """Controllo. Senza `unknown`/`selectors_unknown` una sezione non dice se il ciclo ha determinato ogni nome (senza
    nomi può essere anche un DNS senza risposta): si legge come le sole liste dei trovati, senza «nessuno»."""

    def test_no_names_say_nothing(self, rendered):
        assert rendered.raw("no_unknown_list_none")["intel_tab"] == rendered.raw("plain")["intel_tab"]

    def test_found_names_render_as_the_found_lists_alone(self, rendered):
        assert rendered.raw("no_unknown_list_found")["intel_tab"] == rendered.raw("both_found_lists_only")["intel_tab"]

    @pytest.mark.parametrize("name", ["no_unknown_list_none", "no_unknown_list_found"])
    def test_the_report_says_ok(self, rendered, name):
        assert rendered.status(name) == "ok"


# ── 5. Lettura del marcatore ───────────────────────────────────────────────────────────────────────────────

class TestTheMarkerIsReadByNameFromTheLists:
    def test_marker_keys_that_are_not_found_names_never_reach_the_page(self, rendered):
        tab = rendered.tab("marker_keys_not_in_the_lists")
        text = tab.dns.text()

        assert [g for g in (*_GHOSTS, "selector2") if g in text] == []
        assert "riportat" not in text
        assert tab.from_the_data() == []

    @pytest.mark.parametrize("name", _PROTO_NAMES)
    def test_a_prototype_name_without_its_own_entry_is_not_carried(self, rendered, name):
        tab = rendered.tab("proto_names_without_own_entry")

        assert "riportat" not in tab.row(name)
        assert "riportat" not in tab.segments(list(_PROTO_NAMES))[name]

    @pytest.mark.parametrize("name", _PROTO_NAMES)
    def test_a_prototype_name_with_its_own_entry_is_carried_and_only_then(self, rendered, name):
        tab = rendered.tab("proto_names_with_own_entry")
        row, segment = tab.row(name), tab.segments(list(_PROTO_NAMES))[name]

        if name in _OWN:
            assert "riportat" in row and _DAY in row, row
            assert "riportat" in segment and _DAY in segment, segment
        else:
            assert "riportat" not in row and "riportat" not in segment

    def test_a_proto_key_does_not_carry_the_names_it_holds(self, rendered):
        tab = rendered.tab("proto_key_holding_other_names")

        assert tab.row(_WWW) == "192.0.2.20"
        assert "riportat" not in tab.dkim()


class TestAMarkerEntryCountsOnlyWhenWellFormed:
    """Una voce del marcatore dice «riportato» solo se è propria, è un oggetto e ha `carried_at` stringa non vuota, e
    solo per un nome stringa. `observed_at` decide la data, non se il nome è riportato."""

    @pytest.mark.parametrize("kind", [k for k in _NOT_A_MARKER if k.startswith(("entry-", "carried-at-"))])
    def test_a_malformed_entry_does_not_mark_its_name(self, rendered, kind):
        tab = rendered.tab(f"malformed_marker_{kind}")

        assert "riportat" not in tab.row(_LOGIN)
        assert "riportat" not in tab.segments(["google", "selector1"])["selector1"]

    def test_a_name_that_is_not_a_string_is_never_carried(self, rendered):
        # Il marcatore ha una voce valida sotto «5», la forma di testo del nome numerico.
        tab = rendered.tab("name_not_a_string")

        assert "riportat" not in tab.row("5")
        assert "riportat" not in tab.segments(["5", "google"])["5"]
        assert rendered.status("name_not_a_string") == "ok"


# ── 6. Valori ostili ───────────────────────────────────────────────────────────────────────────────────────

class TestHostileValuesAreText:
    @pytest.mark.parametrize("name", ["hostile_names", "hostile_names_carried", "hostile_tested", "date_hostile",
                                      "marker_keys_not_in_the_lists"])
    def test_no_element_and_no_attribute_comes_from_the_data(self, rendered, name):
        tab = rendered.tab(name)

        assert tab.from_the_data() == []

    def test_hostile_undetermined_names_are_listed_as_text_once(self, rendered):
        tab = rendered.tab("hostile_names")
        sub, dkim = tab.subdomain_text(), tab.dkim()

        for name in _HOSTILE_NAMES:
            assert sub.count(name) == 1 and dkim.count(name) == 1, name[:40]
        assert _first_number_after("non determinat", sub) == len(_HOSTILE_NAMES), sub[:300]
        assert "riportat" not in sub and "riportat" not in dkim

    def test_hostile_carried_names_are_text_with_their_mark(self, rendered):
        tab = rendered.tab("hostile_names_carried")

        for name in _HOSTILE_NAMES[:5]:
            row = tab.row(name)
            assert "riportat" in row and _DAY in row, (name, row)
        assert tab.dkim().count("riportat") == 5

    def test_a_hostile_number_tested_is_text(self, rendered):
        tab = rendered.tab("hostile_tested")

        assert "<b id=x74-tested>" not in tab.markup and "<b id=x74-selectors-tested>" not in tab.markup


# ── 7. Campi malformati ────────────────────────────────────────────────────────────────────────────────────

class TestMalformedFieldsDoNotThrow:
    @pytest.mark.parametrize("name", _MALFORMED)
    def test_the_report_and_the_intel_tab_render(self, rendered, name):
        rendered.raw(f"malformed_{name}")

    @pytest.mark.parametrize("name", [n for n in _MALFORMED if n.startswith(("sub_unknown_", "marker_"))
                                      and not n.endswith("_nothing_active")])
    def test_the_found_subdomains_are_still_shown(self, rendered, name):
        tab = rendered.tab(f"malformed_{name}")

        assert tab.row(_WWW).startswith("192.0.2.20")

    @pytest.mark.parametrize("name", [n for n in _MALFORMED if n.startswith("marker_")])
    def test_a_malformed_marker_marks_no_name_without_an_entry(self, rendered, name):
        tab = rendered.tab(f"malformed_{name}")

        assert "riportat" not in tab.row(_WWW)
        assert "riportat" not in tab.segments(["google", "selector1"])["google"]

    def test_bad_items_in_unknown_leave_the_named_ones_listed(self, rendered):
        tab = rendered.tab("malformed_sub_unknown_bad_items")

        assert len(_token(_VPN).findall(tab.subdomain_text())) >= 1
        assert "[object Object]" not in tab.subdomain_text()


class TestTheReportWithANullEntryInActive:
    @pytest.mark.parametrize("name", _REPORT_ONLY)
    def test_the_report_renders(self, rendered, name):
        assert "Module status" in rendered.report(name)

    def test_the_names_beside_the_null_entry_still_count(self, rendered):
        assert not rendered.status("report_active_null_entry").startswith("ok")


# ── 8. Snapshot del riporto vero ───────────────────────────────────────────────────────────────────────────

_FOUND = [_col31._WWW, _col31._MAIL, _col31._AUTODISCOVER, _col31._LOGIN]


class TestSnapshotsSavedByTheCarryOver:
    def test_precondition_the_carry_over_marked_the_cut_names(self, col31_dns):
        partial = col31_dns["col31_partial"]

        assert partial["subdomains"]["carried_over"][_col31._LOGIN]["observed_at"] == _T0
        assert set(partial["email_auth"]["dkim"]["carried_over"]) == {"selector1"}
        assert _col31._LOGIN in partial["subdomains"]["unknown"]

    def test_a_partial_cycle_marks_the_carried_names_and_lists_the_undetermined_ones(self, rendered):
        tab = rendered.tab("col31_partial")
        rows = {n: tab.row(n) for n in _FOUND}
        segments = tab.segments(["google", "selector1", "k1"])

        assert "riportat" in rows[_col31._LOGIN] and _DAY in rows[_col31._LOGIN], rows
        assert [n for n in _FOUND if n != _col31._LOGIN and "riportat" in rows[n]] == []
        assert _first_number_after("non determinat", tab.subdomain_text()) == 1
        assert len(_token(_sub("vpn")).findall(tab.subdomain_text())) == 1
        assert len(_token(_col31._LOGIN).findall(tab.subdomain_text())) == 1
        assert "riportat" in segments["selector1"] and _DAY in segments["selector1"]
        assert "riportat" not in segments["google"]
        assert _first_number_after("non determinat", tab.dkim()) == 1

    def test_a_partial_cycle_is_not_dns_ok_in_the_report(self, rendered):
        assert not rendered.status("col31_partial").startswith("ok")

    def test_a_cut_stage_marks_every_carried_name_and_counts_the_rest(self, rendered):
        tab = rendered.tab("col31_stage_cut")
        segments = tab.segments(["google", "selector1"])

        assert all("riportat" in tab.row(n) for n in _FOUND)
        assert _first_number_after("non determinat", tab.subdomain_text()) == 25 - len(_FOUND)
        assert all("riportat" in s for s in segments.values()), segments
        assert _first_number_after("non determinat", tab.dkim()) == 18 - 2
        assert "nessun" not in tab.subdomain_text() + tab.dkim()
        assert not rendered.status("col31_stage_cut").startswith("ok")

    @pytest.mark.parametrize("name", ["col31_total_failure", "col31_section_none"])
    def test_a_failed_module_keeps_every_name_marked(self, rendered, name):
        tab = rendered.tab(name)
        segments = tab.segments(["google", "selector1"])

        assert all("riportat" in tab.row(n) and _DAY in tab.row(n) for n in _FOUND), name
        assert all("riportat" in s and _DAY in s for s in segments.values()), segments
        assert "non determinat" not in tab.subdomain_text() + tab.dkim()

    def test_a_first_cycle_cut_has_everything_undetermined_and_nothing_carried(self, rendered):
        tab = rendered.tab("col31_first_cycle_cut")

        assert _first_number_after("non determinat", tab.subdomain_text()) == 25
        assert _first_number_after("non determinat", tab.dkim()) == 18
        assert "riportat" not in tab.dns.text() and "nessun" not in tab.subdomain_text() + tab.dkim()
        assert not rendered.status("col31_first_cycle_cut").startswith("ok")

    def test_control_a_healthy_cycle_renders_as_the_found_lists_alone(self, rendered):
        assert rendered.raw("col31_healthy")["intel_tab"] == rendered.raw("col31_healthy__found_lists_only")["intel_tab"]
        assert rendered.status("col31_healthy") == "ok"

    def test_hostile_names_kept_by_a_failed_module_are_marked_text(self, rendered):
        tab = rendered.tab("col31_hostile_names_total_failure")
        names = ("__proto__", "constructor", "toString", "<img src=x onerror=probe74(5)>")
        segments = tab.segments(["google", "selector1", "__proto__", "constructor"])

        assert all("riportat" in tab.row(n) and _DAY in tab.row(n) for n in (*_FOUND, *names))
        assert all("riportat" in s and _DAY in s for s in segments.values()), segments
        assert tab.from_the_data() == []


class TestNoneKeptByAFailedModuleShowsItsAge:
    """Un precedente senza nomi, poi un guasto totale o `/dns` senza risposta: la sezione salvata è quella del
    precedente, intera, e non ha marcatori di nome (non ci sono nomi). La riga «nessun…» porta la data di
    quell'osservazione, non quella del ciclo."""

    _KEPT = ["col31_none_kept_total_failure", "col31_none_kept_section_none"]

    @pytest.mark.parametrize("name", _KEPT)
    def test_precondition_the_saved_section_is_the_previous_one_without_name_markers(self, col31_dns, name):
        dns = col31_dns[name]

        assert dns["timestamp"] == _T0
        assert "carried_over" not in dns["subdomains"] and "carried_over" not in dns["email_auth"]["dkim"]
        assert dns["subdomains"]["active"] == [] and dns["email_auth"]["dkim"]["selectors_found"] == []

    @pytest.mark.parametrize("name", _KEPT)
    @pytest.mark.parametrize("side", _SIDES)
    def test_the_none_line_shows_the_previous_observation_not_the_cycle(self, rendered, name, side):
        observed = _observed(_none_line(rendered.tab(name), side))

        assert _DAY in observed and _CYCLE_DAY not in observed, observed

    def test_carried_subdomains_and_a_kept_dkim_none_both_show_their_age(self, rendered):
        tab = rendered.tab("col31_none_kept_mixed")
        observed = _observed(_none_line(tab, "dkim"))

        assert all("riportat" in tab.row(n) and _DAY in tab.row(n) for n in _FOUND)
        assert _DAY in observed and _CYCLE_DAY not in observed, observed

    def test_precondition_a_fresh_cycle_saves_its_own_observation(self, col31_dns):
        assert col31_dns["col31_fresh_none"]["timestamp"].startswith(_CYCLE_DAY)

    @pytest.mark.parametrize("side", _SIDES)
    def test_a_fresh_cycle_without_names_shows_its_own_date(self, rendered, side):
        observed = _observed(_none_line(rendered.tab("col31_fresh_none"), side))

        assert _CYCLE_DAY in observed and _DAY not in observed, observed


# ── 9. Costo ───────────────────────────────────────────────────────────────────────────────────────────────

# Conta, dentro un contesto `vm` con lo script vero della pagina, gli elementi che i metodi di `Array.prototype`
# scorrono durante una resa: ogni chiamata aggiunge la lunghezza dell'array su cui lavora. Un `Set` o una mappa non
# si contano; una ricerca in un array dentro un ciclo sì. Un controllo misura una scansione quadratica nota.
_COST_JS = r"""
"use strict";
const fs = require("fs");
const vm = require("vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const element = () => new Proxy(function () {}, {
  get: (_target, key) => key === Symbol.toPrimitive ? () => ""
    : key === "value" || key === "innerHTML" || key === "textContent" ? ""
    : key === "classList" ? { add() {}, remove() {}, toggle() {}, contains: () => false }
    : key === "style" || key === "dataset" ? {} : element(),
  set: () => true,
  apply: () => element(),
});
const storage = { getItem: () => null, setItem() {}, removeItem() {} };
const sandbox = {
  console: { log() {}, info() {}, warn() {}, error() {}, debug() {} },
  document: { getElementById: () => element(), querySelector: () => element(), querySelectorAll: () => [],
              createElement: () => element(), addEventListener() {}, body: element() },
  sessionStorage: storage, localStorage: storage, navigator: {}, location: { hash: "", href: "" },
  fetch: () => new Promise(() => {}), setTimeout: () => 0, clearTimeout() {}, setInterval: () => 0,
  clearInterval() {}, requestAnimationFrame: () => 0, alert() {}, confirm: () => true, prompt: () => null,
  URL: { createObjectURL: () => "" }, Blob: function () {},
};
sandbox.window = sandbox;
const context = vm.createContext(sandbox);
for (const m of fs.readFileSync(input.page, "utf8").matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)) {
  vm.runInContext(m[1], context, { filename: "dashboard_app.html", timeout: 20000 });
}
function driver(input) {
  const methods = ["includes", "indexOf", "lastIndexOf", "find", "findIndex", "findLast", "findLastIndex", "some",
                   "every", "filter", "map", "flatMap", "forEach", "reduce", "reduceRight", "join"];
  let scanned = 0;
  for (const name of methods) {
    const original = Array.prototype[name];
    Array.prototype[name] = function (...args) { scanned += this.length >>> 0; return original.apply(this, args); };
  }
  const measure = fn => { scanned = 0; fn(); return scanned; };
  const out = { cases: {}, control: {} };
  for (const c of input.cases) {
    const snapshot = { available: true, history: [],
                       snapshot: { domain: c.domain, client: "tenant-x", updated_at: c.updated_at, intel: c.intel } };
    out.cases[c.name] = {
      intel_tab: measure(() => { CURRENT_INTEL = snapshot; renderIntelTab(); }),
      report: measure(() => buildHtmlReport({ client: "tenant-x", report_generated: c.updated_at, cases: [],
                                              targets: [], watchlist: [], case_count: 0,
                                              intel_snapshots: { [c.domain]: snapshot } })),
    };
  }
  for (const n of input.sizes) {
    const names = Array.from({ length: n }, (_, i) => "n" + i);
    out.control[n] = measure(() => names.forEach(x => names.includes(x + "?")));
  }
  return JSON.stringify(out);
}
sandbox.__input = JSON.stringify(input);
process.stdout.write(vm.runInContext("(" + driver.toString() + ")(JSON.parse(__input))", context,
                                     { filename: "driver.js", timeout: 60000 }));
"""
_COST_SIZES = (300, 2400)
_COST_BOUND = 3 * _COST_SIZES[1] / _COST_SIZES[0]      # lineare: circa 8; quadratico: circa 64


def _cost_intel(n):
    """`n` sottodomini attivi e riportati più `n` non determinati; lo stesso per i selettori."""
    active = [_active(f"a{i}.{_DOMAIN}") for i in range(n)]
    found = [f"f{i}" for i in range(n)]
    return _intel(
        subdomains=_subs(active=active, unknown=[a["fqdn"] for a in active] + [f"u{i}.{_DOMAIN}" for i in range(n)],
                         marker={a["fqdn"]: _entry() for a in active}),
        dkim=_dkim(found=found, unknown=found + [f"u{i}" for i in range(n)], marker={s: _entry() for s in found}))


@pytest.fixture(scope="module")
def cost():
    node = _node()
    payload = {"page": str(_PAGE), "sizes": list(_COST_SIZES),
               "cases": [{"name": str(n), "domain": _DOMAIN, "updated_at": _NOW, "intel": _cost_intel(n)}
                         for n in _COST_SIZES]}
    return _run_node([node, "-e", _COST_JS], payload, "il conteggio del costo")


class TestTheCostGrowsWithTheLengthOfTheLists:
    def test_control_the_count_sees_a_quadratic_scan(self, cost):
        small, big = (cost["control"][str(n)] for n in _COST_SIZES)

        assert small > 0 and big / small > _COST_BOUND, (small, big)

    @pytest.mark.parametrize("page", ["intel_tab", "report"])
    def test_the_elements_scanned_grow_with_the_lists_not_with_their_square(self, cost, page):
        small, big = (cost["cases"][str(n)][page] for n in _COST_SIZES)

        assert small > 0 and big / small < _COST_BOUND, (small, big)


# ── 10. Tutto reso ─────────────────────────────────────────────────────────────────────────────────────────

def test_every_case_renders_without_throwing(rendered):
    # I casi di `_REPORT_ONLY` fanno sollevare la scheda Intel per una forma fuori contratto: lì conta il report.
    assert rendered.result["load_error"] is None, rendered.result["load_error"]
    thrown = {name: case["error"] for name, case in rendered.result["cases"].items()
              if case["error"] and (name not in _REPORT_ONLY or "buildHtmlReport" in case["error"])}

    assert not thrown, f"la resa solleva su {len(thrown)} snapshot: {thrown}"


def test_the_harness_rendered_every_case(rendered, col31_dns):
    expected = set(_CASES) | set(col31_dns) | {f"{n}__found_lists_only" for n in col31_dns}

    assert set(rendered.result["cases"]) == expected


def test_the_lists_used_here_are_the_ones_dns_tests():
    # Controllo: i conteggi attesi (25, 18) sono quelli degli elenchi che `/dns` prova.
    assert len(DEFAULT_SUBDOMAINS) == 25 and len(DEFAULT_DKIM_SELECTORS) == 18
