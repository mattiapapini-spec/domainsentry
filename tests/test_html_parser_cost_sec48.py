"""Tests per il costo del parser HTML in `/http` — un tag con molti attributi o molti spazi non tiene fermo il
processo (SEC-48).

`detect_hidden_elements` (shared/utils.py) legge form, iframe, pixel e markup morto con `_TagCollector`, una
sottoclasse di `html.parser.HTMLParser`. Tre espressioni regolari della libreria standard hanno una ripetizione
composta che il motore `sre` esegue in una sola chiamata C, spingendo un frame sul proprio stack per ogni
iterazione: `locatetagend` (un'iterazione per attributo, nei tag d'apertura e di chiusura), `tagfind_tolerant`
(una per spazio o `/` dopo il nome del tag) e `attrfind_tolerant` (una per spazio o `/` dopo un attributo). Un tag
con molti attributi o molti spazi, aperto o chiuso, fa quindi una chiamata C lunga quanto il tag, che tiene il GIL
per tutta la sua durata: nel frattempo dashboard, login e sonde di salute dello stesso processo restano fermi.

Comportamento richiesto:

- Su ogni famiglia di corpo ostile nota, la memoria che l'analisi usa non cresce col tag: nessuna chiamata delle
  tre regex cresce con l'ingresso. Un tag d'apertura chiuso con molti attributi costa la sola lista degli attributi
  che il parser consegna al collector.
- Sull'interprete in uso il collector usa davvero il parser a costo limitato, non il ripiego.
- I risultati sono quelli del parser della libreria standard dell'interprete in uso, con un parsing per ciascun
  insieme di tag: stessi tag, attributi, testo sorgente, chiusura, opacità; stessi eventi del parser; stessi
  campi di `detect_hidden_elements`, della risposta di `/http` e degli alert del classificatore. Una lista di
  elementi nascosti contiene solo tag del proprio nome: un `<iframe>` di un pixel non è un pixel di tracciamento.
  Il valore atteso lo calcola il parser standard dentro il test, perché la decodifica dei valori di attributo
  cambia fra le versioni di Python.
- Se gli interni della libreria standard su cui il collector si appoggia mancano o sono cambiati (una regex
  rinominata o con un'altra grammatica, un metodo rinominato, il buffer rinominato), il codice torna al parser
  standard: lento ma con gli stessi risultati.
- Il modulo `html.parser` resta quello della libreria standard per tutto il processo: nessuna sua regex e nessun
  metodo di `HTMLParser` viene sostituito.

Come si misura. La crescita dello stack di `sre` si legge col picco di `tracemalloc` durante un'analisi: è un
conteggio di byte allocati, deterministico e indipendente dal carico della macchina, quindi regge anche col
driver parallelo, dove i tempi non sono affidabili. Il tempo di fermo sul processo vero non è un test della
suite. I casi mirati coprono ciascuna delle tre regex, anche con stringhe su cui una riscrittura plausibile ma
sbagliata della coda di `attrfind_tolerant` cambia il valore di un attributo. Gli interni mancanti si simulano in
un interprete separato, caricando una copia modificata del sorgente di `html.parser` prima di importare il codice.

Interfaccia richiesta al codice: `shared.utils._TagCollector(nomi_dei_tag)` resta la classe (non l'istanza) che
`detect_hidden_elements` usa per il parsing, letta dal modulo a ogni chiamata; il suo risultato è in `.tags`.
`shared.utils._HTML_PARSER_FALLBACK` vale `None` se il collector usa il parser a costo limitato, altrimenti il
motivo per cui è rimasto sul parser standard, deciso dallo stato di `html.parser` visto all'import.

Isolamento di rete: **nessuna connessione**. `/http` gira dietro `TestClient`, con lo scaricamento sostituito da
un sito finto. Domini `.example`.
"""
import base64
import functools
import gc
import importlib.util
import json
import random
import subprocess
import sys
import tracemalloc
import types
from pathlib import Path

import pytest

import shared.utils as utils

_ROOT = Path(__file__).resolve().parent.parent
_KIB = 1024
_MIB = 1024 * _KIB

_SELF = "sito.example"            # il dominio della pagina analizzata
_LEGIT = "sito-cliente.example"   # il dominio legittimo di un cliente, per gli alert del classificatore
_LOOKALIKE = "sito-cllente.example"

# I tag che l'analisi chiede al collector. Gli eventi del parser non dipendono dai tag chiesti, e la raccolta è una
# funzione degli eventi: confrontare eventi e tag dei tre insiemi insieme basta anche per ciascun insieme da solo.
_TAG_SETS = (("iframe", "form", "img"),)


# ── Corpi ostili ──────────────────────────────────────────────────────────────────────────────

_PROSE = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor "

# (inizio, unità ripetuta, fine). Nessuna di queste famiglie fa costruire al parser una lista che cresce col corpo:
# il tag non si chiude, oppure è un tag di chiusura, oppure ha pochi attributi e molti spazi.
_GROWING_FAMILIES = {
    # `locatetagend` su un tag d'apertura mai chiuso: un'iterazione per attributo
    "attr_bare": ("<a", " b", ""),
    "attr_value": ("<a", " b=c", ""),
    "attr_quoted": ("<a", " b=''", ""),
    "attr_slash": ("<a", "/b", ""),
    "nested_open": ("", "<a <b <c d=e ", ""),
    "repeated_tag": ("", "<a" + " b=c" * 2000, ""),
    "input_hidden": ("", "<input type=hidden ", ""),
    "meta_refresh": ("", "<meta http-equiv=refresh ", ""),
    "form": ("", "<form ", ""),
    "div_display": ("", '<div style="display:none', ""),
    "prose": ("<p ", _PROSE, ""),
    # `locatetagend` su un tag di chiusura chiuso
    "endtag_attrs": ("</a", " b=c", ">"),
    # `tagfind_tolerant`: spazi o `/` dopo il nome, nel tag d'apertura e in quello di chiusura
    "name_spaces": ("<a", " ", ">"),
    "name_slashes": ("<a", "/ ", ">"),
    "endtag_name_spaces": ("</a", " ", ">"),
    # `attrfind_tolerant`: spazi dopo un attributo
    "attr_spaces": ("<a b", " ", " c>"),
    "img_attr_spaces": ("<img src=x", " ", " width=1 height=1>"),
}

# Tag d'apertura chiusi con molti attributi: il parser deve consegnare al collector la lista di tutti gli
# attributi, quindi qui la memoria cresce comunque col corpo; conta quanto costa ogni attributo.
_CLOSED_START_TAGS = {
    "a": ("<a", " b=c", ">"),
    "img": ("<img", " b=c", ">"),          # raccolto dal collector
    "iframe": ("<iframe", " b=c", ">"),    # raccolto, e apre una regione opaca mai chiusa
}


def _body(family, size):
    head, unit, tail = family
    n = size - len(head) - len(tail)
    return head + (unit * (n // len(unit) + 1))[:n] + tail


# ── Misura della memoria ──────────────────────────────────────────────────────────────────────

# Crescita del picco fra 64 e 256 KiB sulle famiglie senza lista. Col parser standard lo stack di `sre` cresce di
# 50-230 byte per byte di corpo: 4,0-4,1 MB la famiglia più debole (`div_display`, pochi attributi per byte), 7,8-45 MB
# le altre. Una scansione a blocchi di dimensione fissa ha un picco che non dipende dal corpo (0,1-0,2 MB con 256
# attributi per chiamata): crescita 0. 1 MiB lascia un fattore 4 sotto la famiglia più debole, e qualunque
# dimensione del blocco dà crescita 0.
_GROWTH_SIZES = (64 * _KIB, 256 * _KIB)
_GROWTH_LIMIT = 1 * _MIB
# Byte per attributo sui tag d'apertura chiusi, a 32 KiB (il rapporto non dipende dalla dimensione). La lista che il
# parser costruisce costa ~107 byte per attributo `b=c` (tupla, posto nella lista, oggetti di passaggio); lo stack di
# `sre` del parser standard ~700. 256 sta a un fattore 2,4 dalla prima e 2,7 dal secondo.
_CLOSED_TAG_SIZE = 32 * _KIB
_PER_ATTRIBUTE_LIMIT = 256


def _peak_bytes(function, *args):
    """Picco di memoria allocata (tracemalloc) durante `function(*args)`, sopra quella già in uso."""
    was_tracing = tracemalloc.is_tracing()
    gc.collect()
    if not was_tracing:
        tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        base = tracemalloc.get_traced_memory()[0]
        function(*args)
        return tracemalloc.get_traced_memory()[1] - base
    finally:
        if not was_tracing:
            tracemalloc.stop()


def _analyse(html):
    return utils.detect_hidden_elements(html, self_domain=_SELF)


def _mb(n):
    return f"{n / _MIB:.2f} MB"


# ── Corpus differenziale ──────────────────────────────────────────────────────────────────────

def _page_login(i=0):
    return ('<!DOCTYPE html><html lang="it"><head><meta charset="utf-8"><title>Accedi &mdash; Banca Esempio</title>'
            '<link rel="stylesheet" href="/static/app.css"><style>.hide{display:none}body{font:14px sans-serif}'
            '</style></head><body><div class="box"><img src="/img/logo.svg" alt="Banca Esempio" width="120" '
            f'height="32"><form id="f{i}" method="post" action="https://raccolta{i}.example/post.php" '
            'autocomplete="off"><input type="hidden" name="csrf" value="9f8e7d6c5b4a"><input type="hidden" '
            'name="step" value="1"><label for="u">Utente</label><input id="u" name="username" type="text">'
            '<label for="p">Password</label><input id="p" name="password" type="password">'
            '<button type="submit">Entra</button></form></div>'
            '<form action="https://esfiltra.example/c" style="display:none"><input name="otp"></form>'
            '<iframe src="https://tracker.example/f" width="0" height="0" frameborder="0" '
            'style="visibility:hidden"></iframe><img src="https://pixel.example/p.gif?u=1&amp;v=2" width="1" '
            'height="1" alt=""><script>var a=document.getElementById("u");a&&a.focus();</script></body></html>')


def _page_parking(i=0):
    return ('<html><head><title>dominio-in-vendita.example</title><meta name="robots" content="noindex,nofollow">'
            '<meta http-equiv="refresh" content="30;url=https://lander.parking.example/?d=x"></head><body>'
            '<div id="banner"><h1>Questo dominio potrebbe essere in vendita</h1><p>Contatta il proprietario.</p>'
            '<a href="https://acquista.parking.example/?dom=x&amp;ref=1">Acquista</a></div>'
            '<iframe src="https://ads.parking.example/serve?slot=1" width="728" height="90" scrolling="no"></iframe>'
            '<iframe src="https://ads.parking.example/serve?slot=2" width="300" height="250"><p>Il tuo browser non '
            'supporta gli iframe.<img src="https://beacon.parking.example/b.gif" width="1" height="1"></p></iframe>'
            f'<script>window.park={{"ts":1714200000{i:03d},"id":"a1b2c3"}};</script></body></html>')


def _page_phishing_kit(i=0):
    js = base64.b64encode(b"document.write('<form action=//kit.example/x>');").decode()
    return ('<html><head><title>Verifica account</title></head><body onload="init()">'
            '<div class="hidden"><form action="next.php" method="POST"><input type="hidden" name="t" value="1">'
            '<input type="password" name="pin"></form> fase successiva preparata ma non ancora visibile</div>'
            f'<script>function init(){{eval(atob("{js}"));}}var _0x1=["\\x68\\x74\\x74\\x70","\\x6c\\x6f\\x63"];'
            '</script><!-- <form action="https://vecchio.example/old.php"><input type=hidden name=x></form> -->'
            '<img src=data:image/gif;base64,R0lGODlhAQABAAAAACw= width=1 height=1>'
            '<div style="position:absolute;left:-9999px">testo fuori schermo con parole chiave di accesso</div>'
            '</body></html>')


def _page_blog(i=0, posts=30):
    body = "".join(f'<article id="post-{k}" class="post"><h2><a href="https://blog.example/p/{k}">Titolo {k}</a>'
                   f'</h2><p>Testo dell\'articolo numero {k} con <b>grassetto</b> e <i>corsivo</i> &amp; un link.</p>'
                   f'<img src="https://blog.example/wp-content/uploads/{k}.jpg" width="640" height="480" alt="" '
                   f'loading="lazy"><!-- articolo {k} --></article>\n' for k in range(posts))
    return ('<!DOCTYPE html><html><head><title>Blog di esempio &#8211; notizie</title>'
            '<script>window._cfg={"base":"https:\\/\\/blog.example\\/","v":"6.5"};if(1<2&&3>1){}</script>'
            '<style>img.e{display:inline!important}</style></head><body class="home">'
            f'<header><nav><ul><li><a href="/">Home</a></li></ul></nav></header><main>{body}</main>'
            '<div class="cookie hidden" style="display:none">Usiamo cookie tecnici per il funzionamento del sito.</div>'
            '<footer>&copy; 2026 Blog</footer></body></html>')


def _page_spa(i=0):
    return ('<!doctype html><html><head><meta charset="utf-8"><title>App</title><link rel="icon" href="data:,">'
            '<script defer src="/static/js/main.a1b2c3.js"></script></head><body>'
            '<noscript>Abilita JavaScript per usare questa applicazione.</noscript><div id="root"></div></body></html>')


def _page_aspnet_viewstate(i=0, kib=96):
    state = base64.b64encode(bytes((k * 7 + i) % 256 for k in range(kib * 768))).decode()
    return ('<html><head><title>Portale</title></head><body><form method="post" action="./Login.aspx" id="form1">'
            f'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="{state}" />'
            '<input type="hidden" name="__EVENTVALIDATION" value="abc123" /><input name="txtUser" type="text" />'
            '<input name="txtPwd" type="password" /><input type="submit" value="Accedi" /></form></body></html>')


def _page_svg(i=0, n=400):
    d = " ".join(f"L{k % 97} {k % 89}" for k in range(n))
    return ('<html><body><svg width="200" height="200" viewBox="0 0 200 200">'
            f'<path d="M0 0 {d} Z" fill="#333" stroke="#000" stroke-width="1"/></svg>'
            '<img src="data:image/svg+xml;base64,PHN2Zy8+" width="16" height="16"></body></html>')


def _page_entities(i=0):
    return ('<html><head><title>Prezzi &euro; &lt;scontati&gt; &amp; offerte &#x263A;</title></head><body>'
            '<textarea name="note">&lt;b&gt;non è markup&lt;/b&gt; &copy;</textarea>'
            '<img src="/p?a=1&copy=2&amp;b=3&notin;x" width="1" height="1" alt="&quot;q&quot;">'
            '<img src="https://pixel.example/p.gif?a=1&copy=2&not=3&x=4" width=1 height=1>'
            '<a href="/x?lang=it&region=eu">link</a></body></html>')


def _page_malformed(i=0):
    return ('<html><body><div class="a"><p>paragrafo non chiuso<div id=x class=\'y\'>'
            '<img/src="https://cdn.esempio.example/i.png"/width=1/height=1>'
            '<form action=/f method=post style="display:none"/><input type=hidden name=a value=b>'
            '<iframe src=//frame.example/x width=0 height=0 /><br/><hr / ></div >'
            '<a href="x" title="con > dentro">ok</a><a href=y title=\'apice " misto\'>ok</a>'
            '</div foo="bar"></body></html>')


def _page_newsletter(i=0):
    cell = ('<td align="left" valign="top" width="300" bgcolor="#ffffff" style="padding:0;margin:0;border:0" '
            'class="c" id="c{k}" data-a="1" data-b="2" data-c="3" role="presentation">cella {k}</td>')
    rows = "".join("<tr>" + cell.format(k=k) + cell.format(k=k + 1) + "</tr>" for k in range(0, 60, 2))
    return (f'<html><body><table width="600" cellpadding="0" cellspacing="0" border="0" align="center">{rows}</table>'
            '<img src="https://open.newsletter.example/o.gif?id=42" width="1" height="1" border="0" '
            'style="display:block"></body></html>')


def _page_redirect(i=0):
    return ('<html><head><meta http-equiv="refresh" content="0; url=https://destinazione.example/landing">'
            '<title>Reindirizzamento</title></head><body><script>setTimeout(function(){window.location='
            '"https://destinazione.example/l"},100)</script><p>Reindirizzamento in corso&hellip;</p></body></html>')


def _page_iframe_fallback(i=0):
    return ('<html><body><iframe src="/embed"><form action="https://raccolta.example/x"><input type=password '
            'name=p></form><img src="https://beacon.example/p.gif" width="1" height="1"><iframe '
            'src="https://annidato.example/"></iframe></iframe><iframe src="https://aperto.example/" width=0 '
            'height=0><img src="https://dopo.example/q.gif"></body></html>')


_PAGES = {f.__name__[len("_page_"):]: f for f in (
    _page_login, _page_parking, _page_phishing_kit, _page_blog, _page_spa, _page_aspnet_viewstate, _page_svg,
    _page_entities, _page_malformed, _page_newsletter, _page_redirect, _page_iframe_fallback)}

# Casi mirati per ciascuna delle tre regex. Ognuno è un documento; molti sono pixel o iframe nascosti, così una
# differenza nel parser si vede anche nei campi di `detect_hidden_elements`.
_REGEX_CASES = {
    "locatetagend": [
        "<img b=c width=1 height=1 src=x>",
        "<img/src=x/width=1/height=1>",
        "<img src=x width=1 height=1 / >",
        "<img src='a>b' width=1 height=1>",
        '<img src="a>b" width=1 height=1>',
        "<img src=a'b width=1 height=1>",
        "<img 'src=x width=1 height=1>",
        "<img src= x width = 1 height =1>",
        "<img src==x width=1 height=1>",
        "<img src=x=y width=1 height=1>",
        "<img =x width=1 height=1 src=y>",
        '<img src="x"width=1 height=1>',
        "<img src='x'width=1 height=1>",
        "<img src=x\fwidth=1\fheight=1>",
        "<img\fsrc=x\fwidth=1\fheight=1>",
        '<img src="x"\fwidth=1\fheight=1>',
        "<img src=x\x0bwidth=1 height=1>",
        "<img src=x\x00 width=1 height=1>",
        "<img src=x\u00a0width=1 height=1>",
        "<img src=x width=1 height=1 <img src=y width=1 height=1>",
        # apice mai chiuso: senza il lookbehind sul nome il tag si chiuderebbe al `>`
        "<img src='x width=1 height=1>",
        "<img width=1 height=1 src='x <p>testo</p>",
        '<img src="x width=1 height=1> <img width=1 height=1 src=y>',
        '<img a="" b="" width=1 height=1 src=z c="',
        "</img b=c><img src=x width=1 height=1>",
        "<iframe src=//i.example/></iframe b='>'><img src=//d.example/ width=1 height=1>",
        "<iframe src=//i.example/></iframe\f><img src=//d.example/ width=1 height=1>",
        "<iframe src=//i.example/></iframe b=c d><img src=//d.example/ width=1 height=1></iframe>",
        "<iframe width=0 height=0 src=//i.example/ x=\"></iframe>\"><img src=//d.example/ width=1 height=1>",
    ],
    "tagfind_tolerant": [
        "<img/ / /src=x width=1 height=1>",
        "<img/>",
        "<img />",
        "<img/ >",
        "<img//>",
        "<img / />",
        "<img\f/\fsrc=x width=1 height=1>",
        "<img\t\n\r\f>",
        "<img//src=x width=1 height=1//>",
        "<iframe/>after<img src=//d.example/ width=1 height=1>",
        "<iframe//>after<img src=//d.example/ width=1 height=1>",
        "<iframe / >after<img src=//d.example/ width=1 height=1></iframe>",
        "<iframe src=//i.example/></iframe/ /><img src=//d.example/ width=1 height=1>",
        "<iframe src=//i.example/></iframe//><img src=//d.example/ width=1 height=1>",
        "<iframe src=//i.example/></iframe\f/\f><img src=//d.example/ width=1 height=1>",
        "<form/style=display:none/action=//f.example//>",
    ],
    "attrfind_tolerant": [
        # dove una coda «piatta» `[\t\n\r\f /]*(?<!/(?=>))` torna indietro dentro il valore non quotato
        "<img width=1 height=1 xb'=///>",
        "<img width=1 height=1 src=///>",
        "<img width=1 height=1 src=x//>",
        "<img width=1 height=1 src=x/ / />",
        "<img width=1 height=1 '=<\"/>",
        "<img width=1 height=1 ==\r/>/>= x\n\r\n",
        "<img width=1 height=1 b\"=/>''a \"<\"",
        "<img width=1 height=1 src=\"x\"/ />",
        "<img width=1 height=1 src=x / / />",
        "<img src=x /width=1 /height=1>",
        "<img src=x/ width=1/ height=1/>",
        "<img src=x\f/\fwidth=1 height=1>",
        "<form style=display:none action=//f.example/x//>",
        "<form style=display:none action=//f.example/x/ />",
        "<iframe width=0 height=0 src=//i.example///><img src=//d.example/ width=1 height=1></iframe>",
        "<iframe width=0 height=0 src=//i.example/ //><img src=//d.example/ width=1 height=1></iframe>",
        # la decodifica dei valori dopo `attrfind_tolerant` cambia fra 3.12 e 3.13: resta quella dell'interprete
        "<img src=\"https://pixel.example/p.gif?a=1&copy=2&not=3&amp;x=4\" width=1 height=1>",
        "<img src=https://pixel.example/p?a=&#x41;&#65&notin;b&lt width=1 height=1>",
    ],
}


def _many_attributes(count, unit, tag="img", tail=" width=1 height=1 src=//m.example/>"):
    return f"<{tag}" + unit * count + tail


# Tag con più attributi o spazi di quanti una scansione a blocchi ne legga per chiamata: un errore al confine fra
# due blocchi (il lookbehind sul nome, un `/` prima di `>`) cambia il tag.
_BOUNDARY_COUNTS = (255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 4097)
_BOUNDARY_CASES = (
    [_many_attributes(n, unit) for n in _BOUNDARY_COUNTS
     for unit in (" b", " b=c", " b='x'", ' b="x"', "/b", " b/", " 'b", '"b"', "\fb")]
    + [_many_attributes(n, " ", tail=" width=1 height=1 src=//s.example/>") for n in _BOUNDARY_COUNTS]
    + ["<img src=//s.example/" + " " * n + "width=1 height=1/>" for n in _BOUNDARY_COUNTS]
    + ["<img src=//s.example/" + "/ " * n + "width=1 height=1>" for n in _BOUNDARY_COUNTS]
    + ["<img" + "/ " * n + "width=1 height=1 src=//s.example/ / />" for n in _BOUNDARY_COUNTS]
    + ["<iframe src=//i.example/></iframe" + " b=c" * n + "><img src=//d.example/ width=1 height=1>"
       for n in _BOUNDARY_COUNTS]
    + ["<iframe src=//i.example/></iframe" + " " * n + "/><img src=//d.example/ width=1 height=1>"
       for n in _BOUNDARY_COUNTS]
)


def _small_hostile():
    """Le famiglie ostili a dimensioni da corpus (300 B e 2 KiB), anche con un `>` in fondo e con un attributo che
    contiene `>` a metà."""
    families = {**_GROWING_FAMILIES, **{f"closed_{k}": v for k, v in _CLOSED_START_TAGS.items()}}
    for name, family in families.items():
        for size in (300, 2 * _KIB):
            body = _body(family, size)
            yield f"{name}-{size}", body
            yield f"{name}-{size}-gt", body + ">"
            yield f"{name}-{size}-qgt", body[: size // 2] + ' d=">" ' + body[size // 2:]


_SOUP = (
    "<img src=//p.example/p.gif width=1 height=1>", "<img width=1 height=1 src=x/>", "</img>",
    "<iframe src=//i.example/ width=0 height=0>", "</iframe>", "</iframe x=y>", "</iframe/>",
    "<form style=display:none action=//f.example/>", "</form>", "<a b c=d>", "</a >", "<br/>",
    "<!-- <img src=//c.example/ width=1 height=1> -->", "<script>if(a<b){}</script>", "<style>p{}</style>",
    "<textarea><img src=//t.example/></textarea>", "<title>&amp;</title>", "<![CDATA[x]]>", "<!DOCTYPE html>",
    "<?pi?>", "<!x>", "&copy=2", "&#x41;", "&amp;", "&notin;", "testo ", "\n", "<", ">", '"', "'", "=", "/", " ",
    "\f", "\t", "\r", "\x0b", "\x00", "\u00a0", "\u3000", "\u0085", "<img ", "<iframe ", "<form ", "</", "<!--",
    "-->", 'b=">"', " src=", " width=1", " height=1", " style=display:none", " b", " b=c", "/ ", "<a",
)


def _random_documents(seed, count):
    rng = random.Random(seed)
    for k in range(count):
        if k % 3 == 2:   # pagine vere con qualche frammento inserito
            page = rng.choice(list(_PAGES.values()))(k)
            doc = page
            for _ in range(rng.randint(1, 4)):
                at = rng.randrange(len(doc) + 1)
                doc = doc[:at] + rng.choice(_SOUP) + doc[at:]
        else:
            doc = "".join(rng.choice(_SOUP) for _ in range(rng.randint(1, 40)))
        if rng.random() < 0.2:
            doc = doc[: rng.randrange(len(doc) + 1)]
        yield f"random-{seed}-{k}", doc


def _random_tag_bodies(seed, count):
    """Corpi di tag brevi sull'alfabeto delle tre grammatiche, dopo un nome di tag o dopo un attributo."""
    rng = random.Random(seed)
    alphabet = "\t\n\r\f /><a=\"'xb"
    for k in range(count):
        s = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
        prefix = ("<img ", "<img", "<img width=1 height=1 src=", "</iframe")[k % 4]
        lead = "<iframe src=//i.example/>" if prefix == "</iframe" else ""
        yield f"tag-{seed}-{k}", lead + prefix + s + "><img width=1 height=1 src=//d.example/>"


# ── Oracolo: il parser della libreria standard ────────────────────────────────────────────────

# SEC-51 (modifica giustificata, G5): `reset` (sezioni CDATA spente) e `parse_marked_section` sono, come
# `set_cdata_mode` per l'iframe, grammatica di `_TagCollector` e non parsing della libreria: l'oracolo li tiene,
# altrimenti confronterebbe il collector con una grammatica diversa dalla sua invece che col tokenizer standard.
_COLLECTOR_GRAMMAR = ("__init__", "set_cdata_mode", "unknown_decl", "reset", "parse_marked_section")


def _stdlib_parser_methods():
    """I metodi di parsing di `HTMLParser` e della sua base, come li ha la libreria standard in uso: tutti tranne
    i gestori (`handle_*`, `unknown_decl`), `__init__` e `set_cdata_mode`, che `_TagCollector` ridefinisce per
    l'iframe."""
    stdlib = sys.modules["html.parser"].HTMLParser
    methods = {}
    for cls in reversed(stdlib.__mro__[:-1]):
        for name, value in vars(cls).items():
            if isinstance(value, types.FunctionType) and name not in _COLLECTOR_GRAMMAR \
                    and not name.startswith("handle_"):
                methods[name] = value
    return methods


def _stdlib_collector_class(collector_class=None):
    """`_TagCollector` col parser della libreria standard al posto del suo: stessi gestori (quindi stessa
    raccolta di tag), metodi di parsing della libreria standard, e un parsing `feed` + `close` sull'intero corpo
    comunque il chiamante lo consegni (con `feed` o assegnando `rawdata`). `instances` conta gli oggetti creati."""
    base = collector_class or utils._TagCollector
    methods = _stdlib_parser_methods()

    class StdlibCollector(base):
        instances = 0

        def __init__(self, *args, **kwargs):
            self._stdlib_input = []
            super().__init__(*args, **kwargs)
            type(self).instances += 1
            self._no_parser_methods_on_the_instance()

        def _no_parser_methods_on_the_instance(self):
            shadowed = sorted(set(vars(self)) & set(methods))
            assert not shadowed, (f"metodi di parsing assegnati all'istanza, non alla classe: {shadowed}; il "
                                  f"confronto col parser standard non si può fare")

        def feed(self, data):
            self._no_parser_methods_on_the_instance()
            self._stdlib_input.append(data)

        def close(self):
            self._no_parser_methods_on_the_instance()
            text = "".join(self._stdlib_input) + getattr(self, "rawdata", "")
            self._stdlib_input = []
            self.rawdata = ""
            methods["feed"](self, text)
            methods["close"](self)

    for name, method in methods.items():
        if name not in ("feed", "close"):
            setattr(StdlibCollector, name, method)
    return StdlibCollector


class _Events:
    """Registra ogni evento del parser, oltre a raccogliere i tag."""

    def __init__(self, *args, **kwargs):
        self.events = []
        super().__init__(*args, **kwargs)

    def handle_starttag(self, tag, attrs):
        self.events.append(("start", tag, tuple(attrs), self.get_starttag_text()))
        super().handle_starttag(tag, attrs)

    def handle_startendtag(self, tag, attrs):
        self.events.append(("startend", tag, tuple(attrs), self.get_starttag_text()))
        super().handle_startendtag(tag, attrs)

    def handle_endtag(self, tag):
        self.events.append(("end", tag))
        super().handle_endtag(tag)

    def handle_data(self, data):
        if self.events and self.events[-1][0] == "data":   # il testo può arrivare a pezzi: conta il testo
            self.events[-1] = ("data", self.events[-1][1] + data)
        else:
            self.events.append(("data", data))

    def handle_comment(self, data):
        self.events.append(("comment", data))

    def handle_decl(self, decl):
        self.events.append(("decl", decl))

    def handle_pi(self, data):
        self.events.append(("pi", data))

    def unknown_decl(self, data):
        self.events.append(("unknown_decl", data))

    def handle_charref(self, name):
        self.events.append(("charref", name))

    def handle_entityref(self, name):
        self.events.append(("entityref", name))


@functools.lru_cache(maxsize=None)
def _recorder_class(collector_class):
    return type("Recorder", (_Events, collector_class), {})


@functools.lru_cache(maxsize=None)
def _cached_stdlib_collector_class(collector_class, stdlib_html_parser):
    """Una classe per coppia (collector, `HTMLParser` in uso): il secondo argomento conta solo come chiave."""
    return _stdlib_collector_class(collector_class)


def _parse(collector_class, html, tag_names):
    recorder = _recorder_class(collector_class)(tag_names)
    recorder.feed(html)
    recorder.close()
    return {"events": recorder.events, "tags": recorder.tags}


def _parser_difference(html, tag_sets=_TAG_SETS):
    """None se il collector del codice dà gli stessi eventi e tag del parser standard, altrimenti la prima
    differenza."""
    stdlib = _cached_stdlib_collector_class(utils._TagCollector, sys.modules["html.parser"].HTMLParser)
    for tag_names in tag_sets:
        got = _parse(utils._TagCollector, html, tag_names)
        expected = _parse(stdlib, html, tag_names)
        for key in ("tags", "events"):
            if got[key] != expected[key]:
                at = next((i for i, (g, e) in enumerate(zip(got[key], expected[key], strict=False)) if g != e),
                          min(len(got[key]), len(expected[key])))
                return {"tag_names": tag_names, "field": key, "index": at,
                        "got": got[key][at:at + 2], "expected": expected[key][at:at + 2]}
    return None


def _with_stdlib_parser(function, *args):
    """`function(*args)` con il parser della libreria standard in `_TagCollector`; verifica che l'analisi lo usi."""
    original = utils._TagCollector
    stdlib = _stdlib_collector_class(original)
    utils._TagCollector = stdlib
    try:
        result = function(*args)
    finally:
        utils._TagCollector = original
    assert stdlib.instances > 0, ("l'analisi non costruisce il parser con `shared.utils._TagCollector`: il "
                                  "confronto col parser standard non si può fare")
    return result


def _analysis_difference(html):
    """None se `detect_hidden_elements` dà lo stesso risultato col parser standard, altrimenti i due risultati."""
    got = _analyse(html)
    expected = _with_stdlib_parser(_analyse, html)
    if got == expected:
        return None
    return {key: {"got": got.get(key), "expected": expected.get(key)} for key in set(got) | set(expected)
            if got.get(key) != expected.get(key)}


def _first_differences(documents, limit=3):
    found = []
    for name, html in documents:
        difference = _parser_difference(html)
        if difference is None:
            difference = _analysis_difference(html)
        if difference is not None:
            found.append({"document": name, "html": html[:160], "difference": difference})
            if len(found) >= limit:
                break
    return found


def _scenario_report():
    """Eseguito nell'interprete separato degli scenari di ripiego: confronto sul corpus ridotto."""
    documents = [*((f"page-{n}", f()) for n, f in _PAGES.items()),
                 *((f"{r}-{k}", c) for r, cases in _REGEX_CASES.items() for k, c in enumerate(cases)),
                 *((f"boundary-{k}", c) for k, c in enumerate(_BOUNDARY_CASES[::7])),
                 *_random_documents(48, 40)]
    return {"fallback": getattr(utils, "_HTML_PARSER_FALLBACK", "<attributo assente>"),
            "documents": len(documents), "differences": _first_differences(documents)}


# ── (a) Memoria del parser ────────────────────────────────────────────────────────────────────

class TestParserMemoryDoesNotGrowWithTheTag:
    @pytest.mark.parametrize("family", list(_GROWING_FAMILIES))
    def test_peak_memory_of_the_analysis_does_not_grow_with_a_hostile_tag(self, family):
        """Il picco di memoria dell'analisi di un corpo ostile è lo stesso a 64 e a 256 KiB: nessuna chiamata delle
        tre regex del parser tiene uno stack che cresce col tag."""
        _analyse(_body(_GROWING_FAMILIES[family], 4 * _KIB))   # cache delle regex e dei moduli
        small, large = (_peak_bytes(_analyse, _body(_GROWING_FAMILIES[family], size)) for size in _GROWTH_SIZES)

        assert large - small <= _GROWTH_LIMIT, (
            f"«{family}»: picco {_mb(small)} a {_GROWTH_SIZES[0] // _KIB} KiB e {_mb(large)} a "
            f"{_GROWTH_SIZES[1] // _KIB} KiB, crescita {_mb(large - small)} (limite {_mb(_GROWTH_LIMIT)}): lo stack "
            f"di una chiamata del parser cresce col tag")

    @pytest.mark.parametrize("tag", list(_CLOSED_START_TAGS))
    def test_a_closed_start_tag_with_many_attributes_costs_only_its_attribute_list(self, tag):
        """Un tag d'apertura chiuso con migliaia di attributi `b=c`: il parser consegna la lista di tutti gli
        attributi, e l'analisi non usa più di `_PER_ATTRIBUTE_LIMIT` byte per attributo."""
        family = _CLOSED_START_TAGS[tag]
        _analyse(_body(family, 4 * _KIB))
        html = _body(family, _CLOSED_TAG_SIZE)
        attributes = (len(html) - len(family[0]) - len(family[2])) // len(family[1])
        peak = _peak_bytes(_analyse, html)

        assert peak / attributes <= _PER_ATTRIBUTE_LIMIT, (
            f"<{tag}> chiuso con {attributes} attributi: picco {_mb(peak)}, {peak / attributes:.0f} byte per "
            f"attributo (limite {_PER_ATTRIBUTE_LIMIT}; la lista degli attributi ne costa ~100)")

    def test_the_bounded_parser_is_active_on_this_interpreter(self):
        """Il ripiego sul parser standard è per interpreti con interni diversi; su quello in uso non deve
        scattare, altrimenti il costo torna quello del parser standard senza che la suite lo dica."""
        fallback = getattr(utils, "_HTML_PARSER_FALLBACK", "`shared.utils._HTML_PARSER_FALLBACK` non esiste")

        assert fallback is None, (f"il collector è sul parser standard con Python {sys.version.split()[0]}: "
                                  f"{fallback}")


# ── (b) Stessi risultati del parser standard ──────────────────────────────────────────────────

class TestSameResultsAsTheStandardParser:
    @pytest.mark.parametrize("regex", list(_REGEX_CASES))
    def test_targeted_cases_give_the_tags_and_events_of_the_standard_parser(self, regex):
        found = _first_differences((f"{regex}-{k}", case) for k, case in enumerate(_REGEX_CASES[regex]))

        assert not found, f"casi mirati di `{regex}` diversi dal parser standard: {found}"

    def test_tags_longer_than_a_scan_block_give_the_tags_of_the_standard_parser(self):
        found = _first_differences((f"boundary-{k}", case) for k, case in enumerate(_BOUNDARY_CASES))

        assert not found, f"tag con centinaia di attributi o spazi diversi dal parser standard: {found}"

    def test_short_random_tag_bodies_give_the_tags_and_events_of_the_standard_parser(self):
        found = []
        for name, html in _random_tag_bodies(48, 3000):
            difference = _parser_difference(html)
            if difference is not None:
                found.append({"document": name, "html": html, "difference": difference})
                if len(found) >= 3:
                    break

        assert not found, f"corpi di tag diversi dal parser standard: {found}"

    def test_pages_give_the_results_of_the_standard_parser(self):
        found = _first_differences((f"page-{name}", build()) for name, build in _PAGES.items())

        assert not found, f"pagine diverse dal parser standard: {found}"

    def test_small_hostile_bodies_give_the_results_of_the_standard_parser(self):
        found = _first_differences(_small_hostile())

        assert not found, f"corpi ostili piccoli diversi dal parser standard: {found}"

    def test_random_documents_give_the_results_of_the_standard_parser(self):
        found = _first_differences(_random_documents(48, 200))

        assert not found, f"documenti casuali diversi dal parser standard: {found}"


# Documenti dove ogni form è nascosto, ogni img è un pixel, ogni iframe è invisibile e ogni URL è esterno: le liste
# di `detect_hidden_elements` sono allora i tag che il parser standard trova, ciascun insieme col proprio parsing.
_STRUCTURE_UNITS = (
    '<form style="display:none" action=https://f{k}.example/x>', "</form>",
    "<img width=1 height=1 src=https://p{k}.example/p.gif>", "<img width=1 height=1 src=https://q{k}.example/ />",
    "<iframe width=0 height=0 src=https://i{k}.example/>", "<iframe width=0 height=0 src=https://s{k}.example/ />",
    "</iframe>", "</iframe b=c>", "</iframe/>", "testo {k} ",
    "<!-- <iframe width=0 height=0 src=https://c{k}.example/> -->",
    "<script>document.write('<img width=1 height=1 src=https://j{k}.example/>')</script>",
    "<textarea></iframe><form style=display:none action=https://t{k}.example/></textarea>",
    "<img b b b width=1 height=1 src=https://m{k}.example/x" + " b=c" * 300 + ">",
    "<img\fwidth=1\fheight=1\fsrc=https://ff{k}.example/>", "<img width=1 height=1 src=https://r{k}.example///>",
    "<form/style=display:none/action=https://g{k}.example/ />", "<a b" + " " * 600 + "c>",
)


def _structure_documents(seed, count):
    rng = random.Random(seed)
    for k in range(count):
        units = [rng.choice(_STRUCTURE_UNITS).format(k=j) for j in range(rng.randint(1, 30))]
        if rng.random() < 0.3:
            units.append("<iframe width=0 height=0 src=https://aperto.example/>")   # regione mai chiusa
        yield f"structure-{seed}-{k}", "".join(units)


def _stdlib_tags(html, tag_names):
    collector = _cached_stdlib_collector_class(utils._TagCollector, sys.modules["html.parser"].HTMLParser)(tag_names)
    collector.feed(html)
    collector.close()
    return collector.tags


class TestEachHiddenElementListHasTheTagsOfItsName:
    def test_hidden_elements_are_the_tags_the_standard_parser_finds_for_each_tag_set(self):
        """Form, pixel e iframe sono quelli che il parser standard trova con un parsing per insieme di tag, e il
        markup morto i tag opachi del parsing dei tre insiemi: qualunque sia il numero di parsing dell'analisi."""
        mismatches = []
        for name, html in _structure_documents(48, 80):
            found = _analyse(html)
            forms = [t for t in _stdlib_tags(html, ("form",)) if not t["_opaque"]
                     and "display:none" in (t["attrs"].get("style") or "")]
            pixels = [t for t in _stdlib_tags(html, ("img",)) if not t["_opaque"]
                      and t["attrs"].get("width") == "1" and t["attrs"].get("height") == "1"]
            iframes = [t for t in _stdlib_tags(html, ("iframe",)) if not t["_opaque"]]
            dead = [(t["name"], t["attrs"].get("action" if t["name"] == "form" else "src"))
                    for t in _stdlib_tags(html, ("iframe", "form", "img")) if t["_opaque"]]
            expected = {
                "hidden_forms": [t["text"][:300] for t in forms],
                "tracking_pixels": [t["text"][:200] for t in pixels],
                "invisible_iframes": [t["text"][:300] for t in iframes],
                "suspicious_dead_markup": [d for d in dead if d[1]][:20],
            }
            got = {   # le liste vuote non compaiono nel risultato
                "hidden_forms": [f["snippet"] for f in found.get("hidden_forms", [])],
                "tracking_pixels": [p["tag"] for p in found.get("tracking_pixels", [])],
                "invisible_iframes": [i["tag"] for i in found.get("invisible_iframes", [])],
                "suspicious_dead_markup": [(d["type"], d.get("src") or d.get("action"))
                                           for d in found.get("suspicious_dead_markup", [])],
            }
            if got != expected:
                mismatches.append({"document": name, "html": html[:200],
                                   **{k: {"got": got[k], "expected": expected[k]} for k in got
                                      if got[k] != expected[k]}})
                if len(mismatches) >= 2:
                    break

        assert not mismatches, f"elementi nascosti diversi dai tag del parser standard: {mismatches}"

    def test_an_iframe_of_one_pixel_is_not_a_tracking_pixel(self):
        """Un `<iframe width=1 height=1>` e un `<img width=1 height=1>`: il pixel di tracciamento è solo l'img;
        l'iframe è fra gli iframe invisibili."""
        found = _analyse('<iframe width=1 height=1 src="https://cornice.example/i"></iframe>'
                         '<img width=1 height=1 src="https://pixel.example/p.gif">')

        assert [p["src"] for p in found.get("tracking_pixels", [])] == ["https://pixel.example/p.gif"], (
            f"pixel di tracciamento: {found.get('tracking_pixels')}")
        assert [i["src"] for i in found.get("invisible_iframes", [])] == ["https://cornice.example/i"], (
            f"iframe invisibili: {found.get('invisible_iframes')}")


# ── (b) `/http` e alert ───────────────────────────────────────────────────────────────────────

class _FakeSite:
    """Al posto dello scaricamento: risponde 200 con `page` all'URL `http://<dominio>`, altrimenti come una
    connessione rifiutata."""

    def __init__(self):
        self.page = ""

    def fetch(self, url, timeout=15, **kwargs):
        if url.startswith("http://") and not url.startswith("http://www."):
            return {"status_code": 200, "content": self.page.encode("utf-8"), "headers": {"Server": "nginx"},
                    "final_url": url, "error": None, "attempts": 1}
        return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                "error": "connection refused", "attempts": 1}


@pytest.fixture(scope="module")
def http_service():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import services.classifier as classifier
    import services.http_fingerprint as http_fingerprint
    site = _FakeSite()
    original = http_fingerprint.http_get_with_retry
    http_fingerprint.http_get_with_retry = site.fetch
    try:
        with TestClient(http_fingerprint.app) as client:
            yield client, site, classifier
    finally:
        http_fingerprint.http_get_with_retry = original


def _http_and_alerts(service, html):
    """La risposta di `/http` per un sosia e per il dominio legittimo che serve `html`, e da queste gli alert
    del classificatore sul legittimo e il verdetto sul sosia."""
    client, site, classifier = service
    site.page = html
    responses = {}
    for domain in (_LOOKALIKE, _LEGIT):
        response = client.get("/http", params={"domain": domain, "check_www": False})
        assert response.status_code == 200, f"/http ha risposto {response.status_code}: {response.text[:300]}"
        responses[domain] = response.json()
        responses[domain].pop("timestamp")
    current = {"dns": None, "cert": None, "whois": None, "reputation": None, "http": responses[_LEGIT]}
    baseline = {**current, "http": {"checks": [{"url": f"http://{_LEGIT}", "status_code": 200,
                                                "hidden_elements": {"risk_indicators": 0, "summary": []}}]}}
    alerts = json.loads(classifier.baseline_diff(classifier.DiffInput(
        domain=_LEGIT, client="cliente", legitimate=_LEGIT, baseline=baseline, current=current)).body)["alerts"]
    for alert in alerts:
        alert.pop("timestamp", None)
    verdict = json.loads(classifier.classify_variant(classifier.VariantInput(
        domain=_LOOKALIKE, fuzzer="replacement", http=responses[_LOOKALIKE],
        dns={"records": {"A": ["192.0.2.10"], "MX": [], "NS": ["ns1.dns.example"]}})).body)
    return {"http": responses, "alerts": alerts,
            "verdict": {k: verdict.get(k) for k in ("auto_classification", "confidence", "rule", "rationale")}}


class TestHttpResponseAndAlerts:
    def test_http_response_and_classifier_alerts_are_those_of_the_standard_parser(self, http_service):
        documents = [*((f"page-{n}", f()) for n, f in _PAGES.items()),
                     *((f"{r}-{k}", c) for r, cases in _REGEX_CASES.items() for k, c in enumerate(cases[:3])),
                     *list(_structure_documents(49, 2)),
                     ("boundary", _BOUNDARY_CASES[5]), ("hostile", _body(_CLOSED_START_TAGS["img"], 2 * _KIB))]
        mismatches = []
        for name, html in documents:
            got = _http_and_alerts(http_service, html)
            expected = _with_stdlib_parser(_http_and_alerts, http_service, html)
            if got != expected:
                mismatches.append({"document": name, **{k: {"got": got[k], "expected": expected[k]} for k in got
                                                        if got[k] != expected[k]}})
                break

        assert not mismatches, f"/http o alert diversi col parser standard: {mismatches}"


# ── (c) Ripiego sul parser standard ───────────────────────────────────────────────────────────

# Interni della libreria standard che cambiano: ogni scenario carica una copia modificata del sorgente prima di
# importare il codice. Le sostituzioni valgono per tutto il modulo, quindi il parser standard modificato resta
# coerente con sé stesso.
_SCENARIOS = {
    "locatetagend_renamed": {"html.parser": [("locatetagend", "locatetagend_next")]},
    "tagfind_renamed": {"html.parser": [("tagfind_tolerant", "tagfind_next")]},
    "attrfind_renamed": {"html.parser": [("attrfind_tolerant", "attrfind_next")]},
    "grammar_changed": {"html.parser": [(r"\t\n\r\f", r"\t\n\r")]},    # `\f` fuori dagli spazi della grammatica
    "method_renamed": {"html.parser": [("check_for_whole_start_tag", "check_for_whole_start_tag_next")]},
    "buffer_renamed": {"_markupbase": [("rawdata", "buffered_text")], "html.parser": [("rawdata", "buffered_text")]},
    # Grammatica cambiata in un carattere che poche pagine di prova possono non contenere (la tabulazione): la vede il
    # confronto del testo delle regex.
    "tab_changed": {"html.parser": [(r"\t\n\r\f", r"\n\r\f")]},  # la tabulazione fuori dagli spazi della grammatica
    # Un metodo che legge un altro attributo del match di `locatetagend` (il testo invece della fine): cambia qualcosa
    # solo sui tag che passano il confine fra due blocchi, quindi lo vede solo una prova con un tag così.
    "match_text_read": {"html.parser": [("        match = locatetagend.match(rawdata, i+1)\n        assert match\n"
                                         "        j = match.end()\n",
                                         "        match = locatetagend.match(rawdata, i+1)\n        assert match\n"
                                         "        j = i + 1 + len(match.group())\n")]},
    # `feed` che normalizza l'ingresso (qui il form feed in spazio): stesso numero di tag, testo dei tag diverso
    # quando il buffer si assegna senza passare da `feed`.
    "feed_normalizes": {"html.parser": [("        as you want (may include '\\n').\n        \"\"\"\n",
                                         "        as you want (may include '\\n').\n        \"\"\"\n"
                                         "        data = data.replace('\\f', ' ')\n")]},
}

_SCENARIO_SOURCE = r'''
import importlib.util, json, sys
root, tests, scenario = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
sys.path[:0] = [root, tests]
for name in ("_markupbase", "html.parser"):
    if name not in scenario:
        continue
    spec = importlib.util.find_spec(name)
    source = spec.loader.get_source(name)
    if source is None:
        raise SystemExit("sorgente di %s non disponibile: lo scenario non si può costruire" % name)
    changed = source
    for old, new in scenario[name]:
        if old not in changed:
            raise SystemExit("scenario non applicabile: %r non è in %s" % (old, name))
        changed = changed.replace(old, new)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(changed, spec.origin, "exec"), module.__dict__)
    if name == "html.parser":
        sys.modules["html"].parser = module
import test_html_parser_cost_sec48 as sec48
print(json.dumps(sec48._scenario_report(), ensure_ascii=False, default=repr))
'''

_SCENARIO_TIMEOUT_S = 120


@pytest.fixture(scope="module")
def scenario_reports():
    """Un interprete separato per scenario, tutti insieme."""
    procs = {}
    try:
        for name, scenario in _SCENARIOS.items():
            command = [sys.executable, "-I", "-B", "-c", _SCENARIO_SOURCE, str(_ROOT), str(_ROOT / "tests"),
                       json.dumps(scenario)]
            procs[name] = subprocess.Popen(command, cwd=str(_ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True)
        reports = {}
        for name, proc in procs.items():
            try:
                out, err = proc.communicate(timeout=_SCENARIO_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                err = f"scaduti {_SCENARIO_TIMEOUT_S} s. {err}"
            reports[name] = (proc.returncode, out, err)
        return reports
    finally:
        for proc in procs.values():
            if proc.poll() is None:
                proc.kill()
                proc.communicate()


class TestFallbackToTheStandardParser:
    @pytest.mark.parametrize("scenario", list(_SCENARIOS))
    def test_results_are_those_of_the_standard_parser_when_an_internal_changes(self, scenario_reports, scenario):
        code, out, err = scenario_reports[scenario]
        assert code == 0, f"«{scenario}»: l'interprete è terminato con {code}: {err[-1500:]}"
        report = json.loads(out.strip().splitlines()[-1])

        assert report["documents"] > 100
        assert not report["differences"], (
            f"«{scenario}» (ripiego: {report['fallback']!r}): risultati diversi dal parser standard di quella "
            f"libreria: {report['differences']}")


# ── Il modulo `html.parser` resta quello della libreria standard ──────────────────────────────

_UNTOUCHED_SOURCE = r'''
import json, sys
sys.path[:0] = [sys.argv[1]]
import _markupbase
import html.parser as stdlib

def snapshot():
    held = {}
    for label, namespace in (("html.parser", vars(stdlib)), ("_markupbase", vars(_markupbase)),
                             ("HTMLParser", vars(stdlib.HTMLParser)), ("ParserBase", vars(_markupbase.ParserBase))):
        for name, value in namespace.items():
            if name != "__warningregistry__":
                held[label + "." + name] = value
    return held

before = snapshot()
import shared.utils as utils
for html in ("<a" + " b=c" * 3000, "<img src=x" + " " * 3000 + " width=1 height=1>", "</a" + " b" * 3000 + ">",
             "<iframe src=//i.example/><form action=//f.example/></iframe><img src=//p.example/ width=1 height=1>"):
    utils.detect_hidden_elements(html, self_domain="sito.example")
after = snapshot()
changed = sorted(k for k in set(before) | set(after) if k not in before or k not in after or before[k] is not after[k])
print(json.dumps(changed))
'''


class TestStandardLibraryUntouched:
    def test_importing_and_using_the_analysis_replaces_nothing_in_html_parser(self):
        """In un interprete pulito: dopo l'import del codice e qualche analisi, ogni globale di `html.parser` e di
        `_markupbase` e ogni attributo di `HTMLParser` e `ParserBase` è lo stesso oggetto che era prima dell'import."""
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", _UNTOUCHED_SOURCE, str(_ROOT)], cwd=str(_ROOT),
                              capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr[-1500:]
        changed = json.loads(proc.stdout.strip().splitlines()[-1])

        assert not changed, f"il codice sostituisce nomi della libreria standard: {changed}"

    def test_html_parser_in_this_process_matches_its_source(self):
        """In questo processo le regex del modulo `html.parser` e i metodi di `HTMLParser` sono quelli del sorgente
        della libreria standard: nessun import del codice li ha sostituiti."""
        import html.parser as stdlib
        spec = importlib.util.find_spec("html.parser")
        source = spec.loader.get_source("html.parser")
        assert source is not None, "sorgente di html.parser non disponibile: il confronto non si può fare"
        pristine = {}
        exec(compile(source, spec.origin, "exec"), pristine)
        changed = []
        for name, value in pristine.items():
            live = getattr(stdlib, name, None)
            if hasattr(value, "pattern"):
                if (getattr(live, "pattern", None), getattr(live, "flags", None)) != (value.pattern, value.flags):
                    changed.append(name)
            elif isinstance(value, types.FunctionType):
                if getattr(live, "__code__", None) != value.__code__:
                    changed.append(name)
        for name, value in vars(pristine["HTMLParser"]).items():
            if isinstance(value, types.FunctionType):
                live = vars(stdlib.HTMLParser).get(name)
                if getattr(live, "__code__", None) != value.__code__:
                    changed.append("HTMLParser." + name)

        assert not changed, f"in `html.parser` non sono quelli del sorgente: {changed}"
