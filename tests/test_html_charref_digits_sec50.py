"""Tests per i riferimenti numerici lunghi nelle pagine di `/http` — un `&#` seguito da migliaia di cifre non fa
fallire l'analisi (SEC-50).

`detect_hidden_elements` (shared/utils.py) legge form, iframe e pixel con `_TagCollector`, una sottoclasse di
`html.parser.HTMLParser`. Il parser decodifica i riferimenti a caratteri nel testo (anche dentro `textarea`, `title`,
`noscript` e, per il collector, `iframe`) e nei valori di attributo con `html.unescape`, che per un riferimento
decimale converte le cifre con `int()`. `int()` rifiuta con `ValueError` una stringa di più di
`sys.get_int_max_str_digits()` cifre (4300 se il processo non lo cambia), zeri iniziali compresi; i riferimenti
esadecimali non hanno questo limite. L'eccezione esce dal parsing, `/http` risponde 500 e l'analisi HTTP di tutti e
quattro gli URL del dominio va persa: bastano 4,3 KB di cifre per togliere un sosia al controllo HTTP.

Comportamento richiesto:

- `/http` risponde 200 e analizza i quattro URL qualunque sia la lunghezza di un riferimento numerico e il punto in cui
  sta, anche dopo molti KiB dello stesso testo o valore, in ogni contesto in cui il parser decodifica: testo con e
  senza `;`, valore di attributo di un tag raccolto o no, contenuto di `textarea`, `title`, `iframe`, `noscript`, coda
  del documento letta da `close()`; anche se la pagina la serve uno solo dei quattro URL, e fino al tetto dello
  scaricamento (`MAX_FETCH_BODY_BYTES`).
- Tag del collector, eventi del parser e risultato di `detect_hidden_elements` sono quelli del parser della libreria
  standard senza limite di cifre, che su questi riferimenti decodifica come un browser: gli zeri iniziali non contano
  (`&#000…65;` è `A`), un valore oltre U+10FFFF è U+FFFD. Vale col parser a costo limitato di SEC-48 e col parser
  standard del suo ripiego, e con qualunque limite del processo, anche impostato dopo l'import del codice.
- Il lavoro di conversione di un riferimento non cresce col numero delle sue cifre: nessuna chiamata a `int()` riceve
  più cifre del limite minimo dell'interprete (640), anche quando il processo non ha limite.
- Le pagine che il parser della libreria standard legge senza errore col limite del processo danno i suoi stessi
  risultati: anche le cifre lunghe in punti che il parser non decodifica (nomi di attributo, commenti, script) e le
  cifre non ASCII dopo `&#`, che non formano un riferimento.
- Nessun cambiamento per tutto il processo: il codice non imposta il limite di `int()`, che resta quello del processo
  anche durante il parsing, e i moduli `html`, `html.parser` e `_markupbase` restano quelli della libreria standard.
- La riduzione poggia su interni della libreria standard: `goahead` e `parse_starttag`, che decodificano con
  `html.unescape` letto come nome globale, direttamente o attraverso `_unescape_attrvalue`. Se non sono quelli
  attesi, l'import del codice riesce, i metodi della libreria restano tutti (nessun metodo ridotto accanto a uno
  standard, anche quando gli interni di uno solo dei due sono cambiati), un WARNING e `shared.utils._CHARREF_FALLBACK`
  ne danno il motivo, e ogni pagina dà l'esito del parser standard, errore compreso. Sugli interpreti dei test la
  riduzione è attiva (`_CHARREF_FALLBACK` vale `None`), e un test fallisce se non lo è.

Come si misura. L'oracolo è il parser della libreria standard (i metodi di `HTMLParser` sui gestori di
`_TagCollector`, con `convert_charrefs` attivo) con il limite di `int()` tolto per la sola durata del suo parsing e
poi ripristinato; dopo ogni test si verifica che il limite sia quello di prima. I valori decodificati da Chromium 141
per gli stessi frammenti sono scritti nel modulo e confrontati sia con l'oracolo sia col collector. Il ripiego di
SEC-48 e gli altri limiti si provano in interpreti separati: il ripiego caricando prima dell'import del codice una
copia modificata del sorgente di `html.parser`, come in tests/test_html_parser_cost_sec48.py; il limite con
`-X int_max_str_digits` o impostandolo dopo l'import. Il costo si prova senza misurare tempi: in un interprete col
limite a 640, dove `sys.get_int_max_str_digits()` risponde 0 al codice come in un processo senza limite, ogni
conversione di più di 640 cifre solleva; pagine col riferimento lungo quanto il tetto dello scaricamento si leggono
senza errori solo se nessuna conversione riceve le cifre del riferimento intero. Gli interni cambiati si simulano
come il ripiego di SEC-48, con una copia modificata del sorgente di `html.parser` caricata prima del codice, in un
interprete separato che raccoglie i WARNING emessi.

Interfaccia richiesta al codice: `shared.utils._TagCollector(nomi_dei_tag)` resta la classe che
`detect_hidden_elements` usa per il parsing, letta dal modulo a ogni chiamata, col risultato in `.tags`;
`shared.utils._HTML_PARSER_FALLBACK` vale `None` col parser a costo limitato e il motivo del ripiego altrimenti;
`shared.utils._CHARREF_FALLBACK` vale `None` con la riduzione attiva e il motivo altrimenti, scritto anche nel
WARNING; `shared.utils.MAX_FETCH_BODY_BYTES` è il tetto dello scaricamento.

Isolamento di rete: **nessuna connessione**. `/http` gira dietro `TestClient`, con lo scaricamento sostituito da un
sito finto. Domini `.example`.
"""
import contextlib
import functools
import importlib.util
import json
import random
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

import shared.utils as utils

_ROOT = Path(__file__).resolve().parent.parent

_SITE = "sito.example"
_URLS = (f"http://{_SITE}", f"https://{_SITE}", f"http://www.{_SITE}", f"https://www.{_SITE}")
_TAGS = ("iframe", "form", "img")   # i tag che `detect_hidden_elements` chiede al collector

# Il limite di cifre del processo; se è tolto, quello di default, così i riferimenti restano più lunghi del limite di
# un processo che non lo cambia.
_LIMIT = sys.get_int_max_str_digits() or 4300
_LONG = _LIMIT + 700

_DEC = "9" * _LONG                   # decimale oltre il limite: valore oltre U+10FFFF
_ZEROS = "0" * _LONG                 # zeri iniziali oltre il limite
_ZEROS_65 = _ZEROS + "65"            # ... seguiti da 65: `A`
_HEX = "f" * _LONG                   # esadecimale: nessun limite di cifre
_HEX_ZEROS_41 = _ZEROS + "41"        # esadecimale con zeri iniziali, valore 0x41: `A`

_CAP = utils.MAX_FETCH_BODY_BYTES    # tetto dello scaricamento di `/http`


# ── Pagine ────────────────────────────────────────────────────────────────────────────────────

# Un form nascosto, un iframe invisibile e un pixel verso host esterni: ciò che il riferimento non deve far perdere.
_HIDDEN = ('<form style="display:none" action="https://raccolta.example/post"><input type="hidden" name="t" '
           'value="1"><input type="password" name="p"></form>'
           '<iframe src="https://cornice.example/f" width="0" height="0"></iframe>'
           '<img src="https://pixel.example/p.gif" width="1" height="1" alt="">')


def _page(fragment="", title="Accedi"):
    """`fragment` all'inizio del corpo, prima degli elementi nascosti."""
    return (f'<!DOCTYPE html><html lang="it"><head><meta charset="utf-8"><title>{title}</title></head><body>'
            f'{fragment}{_HIDDEN}<p>Contatti</p></body></html>')


def _tail_page(fragment):
    """`fragment` in coda al documento, dopo gli elementi nascosti: lo legge il ramo finale di `close()`."""
    return f'<!DOCTYPE html><html><head><title>Accedi</title></head><body>{_HIDDEN}<p>Contatti</p>{fragment}'


def _repeated(unit, size):
    return unit * max(size // len(unit), 1)


_HTTP_PAGES = {
    "text_with_semicolon": _page(f"<p>Riferimento &#{_DEC}; nel testo</p>"),
    "text_without_semicolon": _page(f"<p>Riferimento &#{_DEC} nel testo</p>"),
    "leading_zeros_then_65": _page(f"<p>Lettera &#{_ZEROS_65};</p>"),
    "attribute_of_an_uncollected_tag": _page(f'<a href="/r?&#{_DEC};">collegamento</a>'),
    "attribute_of_a_collected_form": _page(
        f'<form style="display:none" action="https://raccolta.example/r?&#{_DEC};"><input name="q"></form>'),
    "attribute_of_a_collected_img": _page(f'<img src="https://pixel.example/r.gif?&#{_DEC};" width="1" height="1">'),
    "textarea": _page(f'<textarea name="n">&#{_DEC};</textarea>'),
    "title": _page(title=f"Accedi &#{_DEC};"),
    "iframe_content": _page(f'<iframe src="/incorniciata">&#{_DEC};</iframe>'),
    "noscript": _page(f"<noscript>&#{_DEC};</noscript>"),
    "tail_trailing_ampersand": _tail_page(f"&#{_DEC};&"),
    "tail_unclosed_textarea": _tail_page(f"<textarea>&#{_DEC};"),
    "text_after_a_few_kib": _page(f"<p>{'x' * 5120}&#{_DEC};</p>"),
    "attribute_after_a_few_kib": _page(f'<a href="/r?q={"x" * 5120}&#{_DEC};">collegamento</a>'),
}

# Il riferimento lungo in un punto qualunque dello stesso testo o valore: la decodifica riceve il tratto intero, e un
# riferimento dopo molti caratteri va ridotto come uno all'inizio. `{a}` e `{b}` sono il tratto prima e dopo.
_POSITION_CONTEXTS = {
    "text": "<p>{a}&#{ref};{b}</p>",
    "text_without_semicolon": "<p>{a}&#{ref}{b} fine</p>",
    "attribute_of_a_collected_tag": '<img src="https://pixel.example/p.gif?q={a}&#{ref};{b}" width=1 height=1>',
    "attribute_of_an_uncollected_tag": '<a href="/r?q={a}&#{ref}{b}">x</a>',
    "unquoted_attribute": "<img alt={a}&#{ref};{b} src=/q width=1 height=1>",
    "title": "<title>{a}&#{ref};{b}</title>",
    "textarea": "<textarea>{a}&#{ref};{b}</textarea>",
    "tail_trailing_ampersand": "TAIL{a}&#{ref};{b}&",
    "tail_unclosed_textarea": "TAIL<textarea>{a}&#{ref};{b}",
    "tail_text": "TAIL{a}&#{ref}{b}",
}
_POSITIONS = {"after_300": (300, 0), "after_5_kib": (5 * 1024, 0), "after_64_kib": (64 * 1024, 0),
              "before_5_kib": (0, 5 * 1024), "middle_of_64_kib": (32 * 1024, 32 * 1024)}


def _position_page(context, position, ref=_DEC):
    before, after = _POSITIONS[position]
    fragment = _POSITION_CONTEXTS[context].format(a="x" * before, b="x" * after, ref=ref)
    return _tail_page(fragment[len("TAIL"):]) if fragment.startswith("TAIL") else _page(fragment)


def _position_documents(contexts=_POSITION_CONTEXTS):
    return [(f"position-{context}-{position}", _position_page(context, position))
            for context in contexts for position in _POSITIONS]


def _large_http_page():
    """Grande quanto il tetto dello scaricamento: mezzo tetto di zeri seguiti da 65 nel testo, poi riferimenti oltre il
    limite nel testo e negli attributi, e spazi fino al tetto."""
    half = _CAP // 2
    many = _repeated(f'<p>&#{_DEC};</p><a href="/r?&#{_ZEROS_65};">x</a>', half - 2000)
    page = _page(f"<p>&#{'0' * half}65;</p>{many}")
    return page.replace("<p>Contatti</p>", "<p>Contatti" + " " * (_CAP - len(page.encode("utf-8"))) + "</p>")


def _large_pages():
    """Pagine grandi quanto il tetto dello scaricamento, con un riferimento lungo quasi quanto la pagina, in ogni
    contesto decodificato, o con molti riferimenti oltre il limite."""
    run = _CAP - 2000
    many = _repeated(f'<p>&#{_DEC};</p><a href="/r?&#{_ZEROS_65};">x</a><img alt="&#{_DEC}" src=/q width=1 height=1>',
                     run)
    return [("large-text", _page(f"<p>&#{'9' * run};</p>")),
            ("large-text-zeros-then-65", _page(f"<p>&#{'0' * run}65;</p>")),
            ("large-attribute-of-a-collected-tag", _page(f'<img src="/q?&#{"9" * run};" width=1 height=1>')),
            ("large-attribute-of-an-uncollected-tag", _page(f'<a href="&#{"9" * run}">x</a>')),
            ("large-title", _page(title=f"&#{'9' * run};")),
            ("large-tail", _tail_page(f"&#{'9' * run}")),
            ("large-many-references", _page(many)),
            ("large-text-reference-at-the-end", _page(f"<p>{'x' * (run - _LONG)}&#{_DEC};</p>")),
            ("large-attribute-reference-at-the-end",
             _page(f'<img alt="{"x" * (run - _LONG)}&#{_DEC};" src=/q width=1 height=1>')),
            ("large-title-reference-at-the-end", _page(title=f"{'x' * (run - _LONG)}&#{_DEC};"))]


# Ogni contesto del tokenizzatore, con un riferimento lungo: (frammento, in coda al documento). In testa al corpo il
# frammento precede gli elementi nascosti, che un parsing interrotto perderebbe.
_CONTEXTS = {
    # testo
    "text_decimal_semicolon": (f"<p>&#{_DEC};</p>", False),
    "text_decimal_no_semicolon": (f"<p>&#{_DEC}</p>", False),
    "text_decimal_then_space": (f"<p>&#{_DEC} x</p>", False),
    "text_decimal_then_tag": (f"<p>&#{_DEC}<b>x</b></p>", False),
    "text_hex_semicolon": (f"<p>&#x{_HEX};</p>", False),
    "text_hex_upper_no_semicolon": (f"<p>&#X{_HEX}</p>", False),
    "text_zeros_decimal": (f"<p>&#{_ZEROS_65};</p>", False),
    "text_zeros_hex": (f"<p>&#x{_HEX_ZEROS_41};</p>", False),
    "text_after_a_pixel": ('<img src="https://pixel.example/a.gif" width="1" height="1">'
                           f"<p>&#{_DEC};</p>", False),
    # valori di attributo
    "attribute_img_double_quotes": (f'<img src="/a?&#{_DEC};" width=1 height=1>', False),
    "attribute_img_single_quotes": (f"<img src='/a?&#{_DEC}' width=1 height=1>", False),
    "attribute_img_unquoted": (f"<img src=&#{_DEC}; width=1 height=1>", False),
    "attribute_uncollected_a": (f'<a href="&#{_DEC};">x</a>', False),
    "attribute_uncollected_div": (f'<div title="&#{_DEC}">x</div>', False),
    "attribute_hex": (f'<img src="&#x{_HEX};">', False),
    "attribute_zeros": (f'<img src="&#{_ZEROS_65};">', False),
    "attribute_self_closing": (f'<br data-x="&#{_DEC};"/>', False),
    "attribute_of_an_end_tag": (f'</p title="&#{_DEC};">', False),
    "attribute_name": (f"<img &#{_DEC};=1>", False),
    "tag_name": (f"<a&#{_DEC};>x</a>", False),
    # RAWTEXT e RCDATA
    "script": (f'<script>var a="&#{_DEC};"</script>', False),
    "style": (f"<style>a{{content:'&#{_DEC};'}}</style>", False),
    "xmp": (f"<xmp>&#{_DEC};</xmp>", False),
    "noembed": (f"<noembed>&#{_DEC};</noembed>", False),
    "noframes": (f"<noframes>&#{_DEC};</noframes>", False),
    "iframe_content": (f"<iframe src=/f>&#{_DEC};</iframe>", False),
    "textarea": (f"<textarea>&#{_DEC};</textarea>", False),
    "title": (f"<title>&#{_DEC};</title>", False),
    "noscript": (f"<noscript>&#{_DEC};</noscript>", False),
    # costrutti non decodificati
    "comment": (f"<!-- &#{_DEC}; -->", False),
    "bogus_comment": (f"<!&#{_DEC};>", False),
    "bogus_end_tag": (f"</&#{_DEC};>", False),
    "processing_instruction": (f"<?x &#{_DEC};>", False),
    "doctype": (f"<!DOCTYPE html &#{_DEC};>", False),
    "cdata": (f"<![CDATA[&#{_DEC};]]>", False),
    # coda del documento, letta da `close()`
    "tail_trailing_ampersand": (f"<p>x</p>&#{_DEC};&", True),
    "tail_unclosed_textarea": (f"<p>x</p><textarea>&#{_DEC};", True),
    "tail_unclosed_title": (f"<title>&#{_DEC};", True),
    "tail_unclosed_script": (f"<script>&#{_DEC};", True),
    "tail_unclosed_start_tag": (f'<img src="&#{_DEC};', True),
    "tail_unclosed_comment": (f"<!-- &#{_DEC};", True),
    "tail_text": (f"<p>x</p>&#{_DEC};", True),
    "tail_text_no_semicolon": (f"<p>x</p>&#{_DEC}", True),
}


def _context_page(name):
    fragment, at_end = _CONTEXTS[name]
    return _tail_page(fragment) if at_end else _page(fragment)


# Intorno al limite: decimali e zeri seguiti da 65, nel testo e in un attributo.
_THRESHOLD_CASES = {
    f"{kind}-{n}-{where}": _page(template.format(ref=ref))
    for n in (_LIMIT - 1, _LIMIT, _LIMIT + 1)
    for kind, ref in (("decimal", "&#" + "9" * n + ";"), ("zeros", "&#" + "0" * (n - 2) + "65;"))
    for where, template in (("text", "<p>{ref}</p>"), ("attribute", '<img alt="x{ref}y" src=/q width=1 height=1>'))
}

# Zeri iniziali oltre il limite seguiti da 6, 7 e 8 cifre significative (U+10FFFF è 1114111, sette cifre), valori
# speciali (surrogati, 0x80-0x9F, controlli, non-caratteri) e riferimenti di 8 cifre sotto il limite.
_SIGNIFICANT_DIGIT_CASES = {
    "only_zeros": _page(f"<p>&#{_ZEROS}; &#{_ZEROS}</p>"),
    "six_digits": _page(f"<p>&#{_ZEROS}999999; &#{_ZEROS}65536;</p>"),
    "seven_digits_in_range": _page(f"<p>&#{_ZEROS}1000000; &#{_ZEROS}1114109; &#{_ZEROS}1114111;</p>"),
    "seven_digits_out_of_range": _page(f"<p>&#{_ZEROS}1114112; &#{_ZEROS}9999999;</p>"),
    "eight_digits": _page(f"<p>&#{_ZEROS}10000000; &#{_ZEROS}99999999abc</p>"),
    "special_values": _page(f"<p>&#{_ZEROS}55296; &#{_ZEROS}57343; &#{_ZEROS}128; &#{_ZEROS}159; &#{_ZEROS}13; "
                            f"&#{_ZEROS}1; &#{_ZEROS}65535;</p>"),
    "attribute": _page(f'<img alt="&#{_ZEROS}1114111;&#{_ZEROS}1114112=&#{_ZEROS}=&#{_ZEROS}128" src=/q width=1 '
                       'height=1>'),
    "eight_digits_under_the_limit": _page("<p>&#00000000;&#00000065;&#01114111;&#01114112;&#99999999;&#000000128;</p>"
                                          '<img alt="&#00000000&#01114111;&#000000065=x" src=/q width=1 height=1>'),
}

_HEX_CASES = {
    "long_text": _page(f"<p>&#x{_HEX};</p>"),
    "long_upper_no_semicolon": _page(f"<p>&#X{_HEX}</p>"),
    "zeros_text": _page(f"<p>&#x{_HEX_ZEROS_41};</p>"),
    "zeros_attribute": _page(f'<img alt="&#x{_HEX_ZEROS_41};" src=/q width=1 height=1>'),
    "zeros_then_letters": _page(f"<p>&#x{_ZEROS}41abc &#x0041abc</p>"),
    "zeros_out_of_range": _page(f"<p>&#x{_ZEROS}110000; &#x{_ZEROS}d800;</p>"),
    "digits_only": _page(f"<p>&#x{'1' * _LONG};</p>"),
}

_MIXED_CASES = {
    "text": _page(f"<p>Prezzo &euro; 10 &amp; &#{_DEC}; poi &#65;&#x42; e &copy &#{_ZEROS_65} fine &notin;x</p>"),
    "attribute": _page(f'<img src="https://pixel.example/p?a=1&copy=2&#{_DEC};&amp;b=&#{_ZEROS_65};&#x41" '
                       'width=1 height=1>'),
    "several_references": _page("".join(f"<p>&#{'7' * (_LIMIT + k)};</p>" for k in range(5))),
    "adjacent": _page(f"<p>&#{_DEC}&#{_DEC};&#{_ZEROS_65}&#x{_HEX};</p>"),
    "followed_by_letters": _page(f"<p>&#{_ZEROS_65}abc &#{_DEC}fff</p>"),
    "in_title_and_attribute": _page(f'<a title="&#{_DEC}">x</a>', title=f"&#{_ZEROS_65};"),
}


def _page_login(i=0):
    return ('<!DOCTYPE html><html lang="it"><head><meta charset="utf-8"><title>Accedi &mdash; Banca Esempio</title>'
            '<style>.hide{display:none}</style></head><body><div class="box"><img src="/img/logo.svg" alt="Banca" '
            f'width="120" height="32"><form id="f{i}" method="post" action="https://raccolta{i}.example/post.php">'
            '<input type="hidden" name="csrf" value="9f8e7d6c"><input id="u" name="username" type="text">'
            '<input id="p" name="password" type="password"><button type="submit">Entra</button></form></div>'
            '<form action="https://esfiltra.example/c" style="display:none"><input name="otp"></form>'
            '<iframe src="https://tracker.example/f" width="0" height="0" style="visibility:hidden"></iframe>'
            '<img src="https://pixel.example/p.gif?u=1&amp;v=2" width="1" height="1" alt="">'
            '<script>var a=document.getElementById("u");a&&a.focus();</script></body></html>')


def _page_parking(i=0):
    return ('<html><head><title>dominio-in-vendita.example</title>'
            '<meta http-equiv="refresh" content="30;url=https://lander.parking.example/?d=x"></head><body>'
            '<h1>Questo dominio potrebbe essere in vendita</h1>'
            '<a href="https://acquista.parking.example/?dom=x&amp;ref=1">Acquista</a>'
            '<iframe src="https://ads.parking.example/serve?slot=1" width="728" height="90"></iframe>'
            '<iframe src="https://ads.parking.example/serve?slot=2" width="300" height="250"><p>Nessun iframe.'
            '<img src="https://beacon.parking.example/b.gif" width="1" height="1"></p></iframe>'
            f'<script>window.park={{"ts":1714200000{i:03d}}};</script></body></html>')


def _page_blog(i=0):
    body = "".join(f'<article id="post-{k}"><h2><a href="https://blog.example/p/{k}">Titolo {k}</a></h2>'
                   f'<p>Articolo {k} con <b>grassetto</b> &amp; un link &#8211; fine.</p>'
                   f'<img src="https://blog.example/u/{k}.jpg" width="640" height="480" alt=""></article>'
                   for k in range(5))
    return ('<!DOCTYPE html><html><head><title>Blog di esempio &#8211; notizie</title></head><body>'
            f'<main>{body}</main><div class="cookie" style="display:none">Cookie tecnici.</div>'
            '<footer>&copy; 2026 Blog</footer></body></html>')


def _page_entities(i=0):
    return ('<html><head><title>Prezzi &euro; &lt;scontati&gt; &amp; offerte &#x263A;</title></head><body>'
            '<textarea name="note">&lt;b&gt;non è markup&lt;/b&gt; &copy;</textarea>'
            '<img src="/p?a=1&copy=2&amp;b=3&notin;x" width="1" height="1" alt="&quot;q&quot;">'
            '<img src="https://pixel.example/p.gif?a=1&#65;&#x42;&#0067&not=3" width=1 height=1>'
            '<a href="/x?lang=it&region=eu">link</a></body></html>')


_PAGES = {f.__name__[len("_page_"):]: f for f in (_page_login, _page_parking, _page_blog, _page_entities)}

_SOUP = ("<p>", "</p>", "<img src=//p.example/p.gif width=1 height=1>", "<iframe src=//i.example/ width=0 height=0>",
         "</iframe>", "<form style=display:none action=//f.example/>", "</form>", "<textarea>", "</textarea>",
         "<title>", "</title>", "<noscript>", "</noscript>", "<script>", "</script>", "<!--", "-->", "<a href=",
         '"', "'", "=", " ", "<", ">", "&amp;", "&copy=2", "&#x41;", "&#65", "testo ")


def _reference(rng):
    """Un riferimento numerico decimale, esadecimale o con zeri iniziali, da 1 cifra a oltre il limite."""
    n = rng.choice((1, 2, 7, 8, 9, 50, _LIMIT - 1, _LIMIT, _LIMIT + 1, _LIMIT + 1, _LONG, _LONG, _LONG))
    kind = rng.choice(("decimal", "decimal", "zeros", "hex", "hex_zeros"))
    if kind == "decimal":
        core = "#" + "".join(rng.choices("0123456789", k=n))
    elif kind == "zeros":
        core = "#" + "0" * max(n - 2, 0) + rng.choice(("65", "00", "13", "128", "55296", "1114111", "1114112"))
    elif kind == "hex":
        core = "#" + rng.choice("xX") + "".join(rng.choices("0123456789abcdefABCDEF", k=n))
    else:
        core = "#x" + "0" * max(n - 2, 0) + rng.choice(("41", "0", "d800", "110000"))
    return "&" + core + rng.choice(("", ";", ";", "=", " ", "abc", "<", '"', "'", "&"))


def _random_documents(seed, count):
    """Pagine e frammenti con da 1 a 3 riferimenti in posizioni a caso: nel testo, negli attributi, nei nomi."""
    rng = random.Random(seed)
    for k in range(count):
        if k % 2:
            doc = rng.choice(list(_PAGES.values()))(k)
        else:
            doc = "".join(rng.choice(_SOUP) for _ in range(rng.randint(1, 30)))
        for _ in range(rng.randint(1, 3)):
            at = rng.randrange(len(doc) + 1)
            doc = doc[:at] + _reference(rng) + doc[at:]
        if rng.random() < 0.2:
            doc = doc[: rng.randrange(len(doc) + 1)]
        yield f"random-{seed}-{k}", doc


# Pagine che il parser standard legge senza errore col limite del processo: cifre lunghe dove il parser non decodifica
# (anche nei nomi di attributo e nel testo sorgente di un tag raccolto), riferimenti fino al limite, esadecimali,
# cifre non ASCII dopo `&#` (non formano un riferimento: restano testo).
_READABLE_CASES = {
    **{f"page-{name}": build() for name, build in _PAGES.items()},
    **{f"context-{name}": _context_page(name) for name in (
        "text_hex_semicolon", "text_hex_upper_no_semicolon", "text_zeros_hex", "attribute_hex",
        "attribute_of_an_end_tag", "attribute_name", "tag_name", "script", "style", "xmp", "noembed", "noframes",
        "comment", "bogus_comment", "bogus_end_tag", "processing_instruction", "doctype", "cdata",
        "tail_unclosed_script", "tail_unclosed_start_tag", "tail_unclosed_comment")},
    "attribute_name_of_a_pixel": _page(f"<img width=1 height=1 src=https://pixel.example/n data&#{_DEC}=1>"),
    "attribute_name_of_a_form": _page(f"<form style=display:none action=https://raccolta.example/n &#{_DEC};=1>"),
    "references_at_the_limit": _page(f"<p>&#{'9' * _LIMIT}; &#{'0' * (_LIMIT - 2)}65;</p>"
                                     f'<img alt="&#{"0" * (_LIMIT - 2)}65" src=/q width=1 height=1>'),
    "short_references": _page("<p>&#65;&#0065;&#00000065;&#000000065;&#1114111;&#1114112;&#55296;&#128;&#0;</p>"
                              '<img alt="&#00000065;&#99999999;=x" src=/q width=1 height=1>'),
    "non_ascii_digits": _page("<p>&#" + "٠" * _LONG + "٦٥; &#" + "０" * 8 + "６５;</p>"
                              '<img alt="&#' + "٩" * 9 + '" src=/q width=1 height=1>'),
    # `#` e cifre senza `&` davanti non sono un riferimento, anche accanto a uno che lo è
    "hash_and_digits_next_to_a_reference": _page(
        '<img src="https://pixel.example/p.gif?c=&#169;#000000001" width=1 height=1>'
        '<a href="/r?n=&#38;#000000065;&amp;m=#12345678">x</a><p>&#169; ordine #12345678 e &#38;#000000065;</p>'),
    # un `&#` seguito da cifre e da una lettera esadecimale non si chiude: il resto del documento resta da leggere
    "digits_then_hex_letter": ('<p>prezzo &#1a</p><form style=display:none action=https://raccolta.example/x></form>'
                               '<iframe width=0 height=0 src=https://cornice.example/></iframe>'),
}


# ── Oracolo: il parser della libreria standard, senza limite di cifre ─────────────────────────

@contextlib.contextmanager
def _int_digit_limit_lifted():
    """Limite di `int()` tolto, e poi rimesso com'era anche se il parsing solleva."""
    saved = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(0)
    try:
        yield
    finally:
        sys.set_int_max_str_digits(saved)


def _stdlib_parsing_methods():
    """I metodi di parsing di `HTMLParser` e della sua base come li ha la libreria standard in uso: tutti tranne i
    gestori, `__init__` e `set_cdata_mode`, che `_TagCollector` ridefinisce per l'iframe."""
    stdlib = sys.modules["html.parser"].HTMLParser
    methods = {}
    for cls in reversed(stdlib.__mro__[:-1]):
        for name, value in vars(cls).items():
            if isinstance(value, types.FunctionType) and name not in ("__init__", "set_cdata_mode", "unknown_decl") \
                    and not name.startswith("handle_"):
                methods[name] = value
    return methods


def _oracle_class(collector_class, lift_limit=True, page=None):
    """`collector_class` coi metodi di parsing della libreria standard, `convert_charrefs` attivo e un parsing `feed`
    + `close` dell'intero corpo, comunque il chiamante lo consegni; con `lift_limit` senza limite di cifre per la sola
    durata del parsing. Con `page` legge `page` invece di ciò che riceve, così una trasformazione dell'ingresso prima
    del parsing resta visibile. `instances` conta gli oggetti creati."""
    methods = _stdlib_parsing_methods()

    class Oracle(collector_class):
        instances = 0

        def __init__(self, *args, **kwargs):
            self._oracle_input = []
            super().__init__(*args, **kwargs)
            for name in methods:   # un metodo messo sull'istanza dal costruttore coprirebbe quello della libreria
                vars(self).pop(name, None)
            self.convert_charrefs = True
            type(self).instances += 1

        def feed(self, data):
            self._oracle_input.append(data)

        def close(self):
            text = page if page is not None else "".join(self._oracle_input) + getattr(self, "rawdata", "")
            self._oracle_input = []
            self.rawdata = ""
            with _int_digit_limit_lifted() if lift_limit else contextlib.nullcontext():
                methods["feed"](self, text)
                methods["close"](self)

    for name, method in methods.items():
        if name not in ("feed", "close"):
            setattr(Oracle, name, method)
    return Oracle


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
def _cached_oracle_class(collector_class, lift_limit):
    return _oracle_class(collector_class, lift_limit)


def _drive(collector, html):
    """Come `detect_hidden_elements`: buffer assegnato e `close` col parser a costo limitato, `feed` e `close` col
    ripiego."""
    if utils._HTML_PARSER_FALLBACK is None:
        collector.rawdata = html
    else:
        collector.feed(html)
    collector.close()


def _parse(collector_class, html):
    recorder = _recorder_class(collector_class)(_TAGS)
    _drive(recorder, html)
    return {"tags": recorder.tags, "events": recorder.events}


def _oracle_parse(html, lift_limit=True):
    return _parse(_cached_oracle_class(utils._TagCollector, lift_limit), html)


def _oracle_analysis(html, lift_limit=True):
    """`detect_hidden_elements` con l'oracolo, che legge `html`, al posto del parser del codice; verifica che l'analisi
    lo usi."""
    original = utils._TagCollector
    oracle = _oracle_class(original, lift_limit, page=html)
    utils._TagCollector = oracle
    try:
        result = utils.detect_hidden_elements(html, self_domain=_SITE)
    finally:
        utils._TagCollector = original
    assert oracle.instances > 0, ("l'analisi non costruisce il parser con `shared.utils._TagCollector`: il "
                                  "confronto con la libreria standard non si può fare")
    return result


_DIGIT_RUN = re.compile(r"[0-9a-fA-F]{24,}")


def _abbrev(value, limit=500):
    """Testo leggibile di un valore, con le sequenze lunghe di cifre ridotte alla loro lunghezza."""
    text = json.dumps(value, ensure_ascii=False, default=repr)
    text = _DIGIT_RUN.sub(lambda m: f"{m.group()[:4]}…[{len(m.group())} cifre]", text)
    return text if len(text) <= limit else text[:limit] + "…"


def _parser_difference(html, lift_limit=True):
    """None se il collector del codice dà i tag e gli eventi dell'oracolo, altrimenti la prima differenza."""
    try:
        got = _parse(utils._TagCollector, html)
    except Exception as exc:
        return {"raised": f"{type(exc).__name__}: {str(exc)[:120]}"}
    expected = _oracle_parse(html, lift_limit)
    for key in ("tags", "events"):
        if got[key] != expected[key]:
            at = next((i for i, (g, e) in enumerate(zip(got[key], expected[key], strict=False)) if g != e),
                      min(len(got[key]), len(expected[key])))
            return {"field": key, "index": at, "got": _abbrev(got[key][at:at + 2]),
                    "expected": _abbrev(expected[key][at:at + 2])}
    return None


def _fields_difference(got, expected):
    return {key: {"got": _abbrev(got.get(key)), "expected": _abbrev(expected.get(key))}
            for key in sorted(set(got) | set(expected)) if got.get(key) != expected.get(key)}


def _analysis_difference(html, lift_limit=True):
    """None se `detect_hidden_elements` dà il risultato che dà con l'oracolo, altrimenti i campi diversi."""
    try:
        got = utils.detect_hidden_elements(html, self_domain=_SITE)
    except Exception as exc:
        return {"raised": f"{type(exc).__name__}: {str(exc)[:120]}"}
    expected = _oracle_analysis(html, lift_limit)
    return None if got == expected else _fields_difference(got, expected)


def _first_differences(documents, lift_limit=True, limit=3):
    found = []
    for name, html in documents:
        difference = _parser_difference(html, lift_limit)
        if difference is None:
            difference = _analysis_difference(html, lift_limit)
        if difference is not None:
            found.append({"document": name, "html": _abbrev(html, 160), "difference": difference})
            if len(found) >= limit:
                break
    return found


def _raises_with_the_process_limit(html):
    try:
        _oracle_parse(html, lift_limit=False)
    except ValueError:
        return True
    return False


def _scenario_documents():
    return [*((f"context-{name}", _context_page(name)) for name in _CONTEXTS),
            *((f"threshold-{name}", page) for name, page in _THRESHOLD_CASES.items()),
            *((f"significant-{name}", page) for name, page in _SIGNIFICANT_DIGIT_CASES.items()),
            *((f"hex-{name}", page) for name, page in _HEX_CASES.items()),
            *((f"mixed-{name}", page) for name, page in _MIXED_CASES.items()),
            *_position_documents(),
            *_random_documents(50, 60)]


_NO_CHARREF_FALLBACK = "<attributo `_CHARREF_FALLBACK` assente>"


def _charref_fallback():
    return getattr(utils, "_CHARREF_FALLBACK", _NO_CHARREF_FALLBACK)


def _scenario_report():
    """Eseguito negli interpreti separati: confronto con l'oracolo su contesti, soglia, cifre significative,
    esadecimali, testo misto e documenti a caso."""
    documents = _scenario_documents()
    return {"fallback": getattr(utils, "_HTML_PARSER_FALLBACK", "<attributo assente>"),
            "charref_fallback": _charref_fallback(), "limit": sys.get_int_max_str_digits(), "documents": len(documents),
            "raising_with_the_process_limit": sum(_raises_with_the_process_limit(html) for _, html in documents),
            "differences": _first_differences(documents)}


def _conversion_report():
    """Eseguito negli interpreti separati in cui il codice legge che il processo non ha limite e l'interprete ne ha
    uno: ogni documento si legge col collector e si analizza senza errori. Nessun confronto con l'oracolo, che per
    togliere il limite e rimetterlo lo leggerebbe."""
    documents = [*_scenario_documents(), *_large_pages()]
    failures = []
    for name, html in documents:
        for step in ("collector", "analysis"):
            try:
                if step == "collector":
                    _parse(utils._TagCollector, html)
                else:
                    utils.detect_hidden_elements(html, self_domain=_SITE)
            except Exception as exc:
                failures.append({"document": name, "step": step, "raised": f"{type(exc).__name__}: {str(exc)[:120]}"})
    return {"fallback": getattr(utils, "_HTML_PARSER_FALLBACK", "<attributo assente>"),
            "charref_fallback": _charref_fallback(),
            "limit_read_by_the_code": sys.get_int_max_str_digits(), "interpreter_limit": sys.flags.int_max_str_digits,
            "documents": len(documents),
            "raising_with_the_interpreter_limit": sum(_raises_with_the_process_limit(html) for _, html in documents),
            "failed": len(failures), "failures": failures[:3]}


def _reduced_methods():
    """I metodi in `vars(_TagCollector)` col codice di un metodo della libreria standard e una decodifica diversa
    (`unescape` o `_unescape_attrvalue` nei globali): quelli della riduzione, non quelli del parser di SEC-48."""
    stdlib = {}
    for cls in reversed(sys.modules["html.parser"].HTMLParser.__mro__[:-1]):
        stdlib.update((name, value) for name, value in vars(cls).items() if isinstance(value, types.FunctionType))
    return sorted(name for name, value in vars(utils._TagCollector).items()
                  if isinstance(value, types.FunctionType) and name in stdlib
                  and value.__code__ is stdlib[name].__code__
                  and any(value.__globals__.get(key) is not stdlib[name].__globals__.get(key)
                          for key in ("unescape", "_unescape_attrvalue")))


def _outcome_difference(html):
    """None se il collector del codice dà l'esito del parser standard col limite del processo: gli stessi tag ed
    eventi, o lo stesso `ValueError`."""
    expected_error = _raises_with_the_process_limit(html)
    try:
        _parse(utils._TagCollector, html)
    except ValueError:
        return None if expected_error else {"raised": "ValueError, il parser standard legge la pagina"}
    if expected_error:
        return {"raised": "nessun errore, il parser standard solleva ValueError"}
    return _parser_difference(html, lift_limit=False)


def _guard_report():
    """Eseguito negli interpreti separati con interni della libreria standard cambiati: le pagine leggibili danno i
    risultati del parser standard di quella libreria, col limite del processo, e quelle coi riferimenti lunghi il suo
    stesso esito."""
    documents = [*((f"readable-{name}", html) for name, html in _READABLE_CASES.items()), *_random_documents(51, 160)]
    readable = [(name, html) for name, html in documents if not _raises_with_the_process_limit(html)]
    outcomes = ((f"context-{name}", _outcome_difference(_context_page(name))) for name in _CONTEXTS)
    return {"fallback": getattr(utils, "_HTML_PARSER_FALLBACK", "<attributo assente>"),
            "charref_fallback": _charref_fallback(), "documents": len(readable),
            "differences": _first_differences(readable, lift_limit=False),
            "reduced_methods": _reduced_methods(),
            "outcome_differences": [{"document": name, "difference": difference}
                                    for name, difference in outcomes if difference is not None][:3]}


@pytest.fixture(autouse=True)
def _digit_limit_unchanged_by_the_test():
    before = sys.get_int_max_str_digits()
    yield
    assert sys.get_int_max_str_digits() == before, (
        f"limite di `int()` del processo cambiato da {before} a {sys.get_int_max_str_digits()} durante il test")


# ── `/http` ───────────────────────────────────────────────────────────────────────────────────

class _FakeSite:
    """Al posto dello scaricamento: risponde 200 con la pagina assegnata all'URL, altrimenti come una connessione
    rifiutata."""

    def __init__(self):
        self.pages = {}

    def fetch(self, url, timeout=15, **kwargs):
        html = self.pages.get(url)
        if html is None:
            return {"status_code": None, "content": None, "headers": {}, "final_url": None,
                    "error": "connection refused", "attempts": 1}
        return {"status_code": 200, "content": html.encode("utf-8"), "headers": {"Server": "nginx"},
                "final_url": url, "error": None, "attempts": 1}


@pytest.fixture(scope="module")
def http_service():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    import services.http_fingerprint as http_fingerprint
    site = _FakeSite()
    original = http_fingerprint.http_get_with_retry
    http_fingerprint.http_get_with_retry = site.fetch
    try:
        # Come in produzione: un'eccezione del gestore diventa una risposta 500, non un'eccezione nel test.
        with TestClient(http_fingerprint.app, raise_server_exceptions=False) as client:
            yield client, site
    finally:
        http_fingerprint.http_get_with_retry = original


def _assert_http_analyses_every_url(service, pages):
    """`/http` risponde 200, ogni URL servito è analizzato col risultato dell'oracolo, e il rischio è quello della
    pagina più rischiosa."""
    client, site = service
    site.pages = dict(pages)
    response = client.get("/http", params={"domain": _SITE})

    assert response.status_code == 200, (
        f"/http ha risposto {response.status_code} ({response.text[:120]!r}): l'analisi HTTP di tutti e quattro gli "
        f"URL è persa")
    body = response.json()
    checks = {check["url"]: check for check in body["checks"]}
    assert sorted(checks) == sorted(pages), f"URL analizzati: {sorted(checks)}"
    expected_by_page = {}
    for url, html in pages.items():
        if html not in expected_by_page:
            expected_by_page[html] = json.loads(json.dumps(_oracle_analysis(html)))
        expected = expected_by_page[html]
        got = checks[url]["hidden_elements"]
        assert checks[url]["status_code"] == 200 and got is not None, f"{url}: {_abbrev(checks[url])}"
        assert got == expected, (f"{url}: elementi nascosti diversi da quelli della libreria standard senza limite: "
                                 f"{_fields_difference(got, expected)}")
    risks = [expected["risk_indicators"] for expected in expected_by_page.values()]
    assert body["hidden_elements_risk"] == max(risks) > 0, (
        f"rischio {body['hidden_elements_risk']}, atteso {max(risks)}")


class TestHttpAnalysesPagesWithLongReferences:
    @pytest.mark.parametrize("context", list(_HTTP_PAGES))
    def test_http_answers_200_and_analyses_the_four_urls(self, http_service, context):
        """La stessa pagina sui quattro URL, con un riferimento decimale di più cifre del limite."""
        _assert_http_analyses_every_url(http_service, dict.fromkeys(_URLS, _HTTP_PAGES[context]))

    def test_one_hostile_url_out_of_four_does_not_cost_the_other_three(self, http_service):
        pages = dict.fromkeys(_URLS, _page("<p>Benvenuti</p>"))
        pages[f"https://www.{_SITE}"] = _HTTP_PAGES["title"]

        _assert_http_analyses_every_url(http_service, pages)

    def test_a_hostile_page_as_large_as_the_fetch_cap(self, http_service):
        """Un URL serve una pagina grande quanto il tetto dello scaricamento, piena di riferimenti oltre il limite."""
        large = _large_http_page()
        pages = dict.fromkeys(_URLS, _page("<p>Benvenuti</p>"))
        pages[f"http://{_SITE}"] = large

        assert len(large.encode("utf-8")) == _CAP
        _assert_http_analyses_every_url(http_service, pages)


# ── Stessi risultati della libreria standard senza limite ─────────────────────────────────────

class TestSameResultsAsTheUnlimitedStandardParser:
    @pytest.mark.parametrize("context", list(_CONTEXTS))
    def test_every_tokenizer_context(self, context):
        html = _context_page(context)
        difference = _parser_difference(html) or _analysis_difference(html)

        assert difference is None, f"«{context}»: {difference}"

    @pytest.mark.parametrize("case", list(_THRESHOLD_CASES))
    def test_references_just_below_at_and_just_above_the_limit(self, case):
        html = _THRESHOLD_CASES[case]
        difference = _parser_difference(html) or _analysis_difference(html)

        assert difference is None, f"«{case}»: {difference}"

    @pytest.mark.parametrize("case", list(_SIGNIFICANT_DIGIT_CASES))
    def test_leading_zeros_and_the_number_of_significant_digits(self, case):
        html = _SIGNIFICANT_DIGIT_CASES[case]
        difference = _parser_difference(html) or _analysis_difference(html)

        assert difference is None, f"«{case}»: {difference}"

    @pytest.mark.parametrize("context", list(_POSITION_CONTEXTS))
    def test_a_long_reference_anywhere_in_a_long_text_or_value(self, context):
        """Dopo 300 caratteri, 5 e 64 KiB dello stesso tratto, prima di 5 KiB e a metà di 64 KiB."""
        found = _first_differences(_position_documents((context,)))

        assert not found, f"«{context}»: riferimento in un tratto lungo diverso dalla libreria standard: {found}"

    def test_hexadecimal_references(self):
        found = _first_differences((f"hex-{name}", page) for name, page in _HEX_CASES.items())

        assert not found, f"riferimenti esadecimali diversi dalla libreria standard: {found}"

    def test_long_references_mixed_with_other_text_and_references(self):
        found = _first_differences((f"mixed-{name}", page) for name, page in _MIXED_CASES.items())

        assert not found, f"testo misto diverso dalla libreria standard senza limite: {found}"

    def test_random_documents_with_references_of_every_length(self):
        documents = list(_random_documents(50, 240))
        raising = sum(_raises_with_the_process_limit(html) for _, html in documents)
        found = _first_differences(documents)

        assert raising >= 20, f"solo {raising} documenti oltre il limite: il corpus non prova il difetto"
        assert not found, f"documenti diversi dalla libreria standard senza limite: {found}"


# Valori decodificati da Chromium 141 per gli stessi frammenti (riferimenti di 5000 cifre): il valore di `alt` o il
# testo dell'elemento. Restano fuori i casi in cui la libreria standard differisce dal browser indipendentemente dalla
# lunghezza del riferimento: controlli e non-caratteri, come `&#1;` o `&#1114111;`, che la libreria toglie.
_BROWSER_VALUES = {
    "text_decimal_over_the_limit": (f"<p>&#{_DEC};</p>", "�"),
    "text_decimal_without_semicolon": (f"<p>&#{_DEC}</p>", "�"),
    "text_decimal_then_letters": (f"<p>&#{_DEC}abc</p>", "�abc"),
    "text_leading_zeros_then_65": (f"<p>&#{_ZEROS_65};</p>", "A"),
    "text_leading_zeros_then_65_then_letters": (f"<p>&#{_ZEROS_65}abc</p>", "Aabc"),
    "text_only_zeros": (f"<p>&#{_ZEROS};&#00000000;</p>", "��"),
    "text_seven_significant_digits": (f"<p>&#{_ZEROS}1000000;&#0000000065536;</p>", "\U000f4240\U00010000"),
    "text_eight_significant_digits": (f"<p>&#{_ZEROS}10000000;&#00000001114112;</p>", "��"),
    "text_hex_over_the_limit": (f"<p>&#x{_HEX};</p>", "�"),
    "text_hex_leading_zeros_then_41": (f"<p>&#x{_HEX_ZEROS_41};</p>", "A"),
    "textarea": (f"<textarea>&#{_DEC};</textarea>", "�"),
    "title": (f"<title>&#{_DEC};</title>", "�"),
    "attribute": (f'<img alt="/r?&#{_DEC};">', "/r?�"),
    "attribute_without_semicolon": (f'<img alt="/r?&#{_DEC}=1">', "/r?�=1"),
    "attribute_leading_zeros_then_65": (f'<img alt="&#{_ZEROS_65};">', "A"),
    "attribute_hex_leading_zeros_then_41": (f'<img alt="&#x{_HEX_ZEROS_41};">', "A"),
    "attribute_seven_and_eight_significant_digits": (f'<img alt="&#{_ZEROS}999999;&#{_ZEROS}99999999">',
                                                     "\U000f423f�"),
    "text_short_out_of_range": ("<p>&#1114112;&#0;&#xD800;&#128;&#13;</p>", "���€\r"),
}


def _decoded(result):
    """Il valore di `alt` del primo `<img>`, oppure il testo del documento."""
    if result["tags"]:
        return result["tags"][0]["attrs"]["alt"]
    return "".join(event[1] for event in result["events"] if event[0] == "data")


class TestDecodedValuesAreThoseOfABrowser:
    @pytest.mark.parametrize("case", list(_BROWSER_VALUES))
    def test_decoded_value(self, case):
        """Il collector e l'oracolo danno il valore del browser: U+FFFD oltre U+10FFFF, zeri iniziali ignorati."""
        html, browser = _BROWSER_VALUES[case]
        oracle = _decoded(_oracle_parse(html))
        got = _decoded(_parse(utils._TagCollector, html))

        assert oracle == browser, f"«{case}»: oracolo {oracle!r}, browser {browser!r}"
        assert got == browser, f"«{case}»: collector {got!r}, browser {browser!r}"


# ── Altre configurazioni: ripiego di SEC-48, altri limiti del processo, costo della conversione ─

# Ogni scenario gira in un interprete separato. Il ripiego si ottiene come in tests/test_html_parser_cost_sec48.py:
# una copia modificata del sorgente di `html.parser`, coerente con sé stessa, caricata prima del codice.
_FALLBACK_SCENARIOS = {
    "locatetagend_renamed": {"sources": {"html.parser": [("locatetagend", "locatetagend_next")]}},
    "method_renamed": {"sources": {"html.parser": [("check_for_whole_start_tag", "check_for_whole_start_tag_next")]}},
}
_LIMIT_SCENARIOS = {
    "limit_640_at_start": {"xoption": "int_max_str_digits=640", "expected_limit": 640},
    "limit_640_after_import": {"runtime_limit": 640, "expected_limit": 640},
    "no_limit": {"xoption": "int_max_str_digits=0", "expected_limit": 0},
}
# L'interprete ha il limite minimo (640) e `sys.get_int_max_str_digits()` risponde 0 al codice, dall'import o dopo:
# il codice si comporta come in un processo senza limite, e una conversione di più di 640 cifre solleva.
_CONVERSION_SCENARIOS = {
    "code_reads_no_limit_from_import": {"xoption": "int_max_str_digits=640", "code_reads_no_limit": "from_import"},
    "code_reads_no_limit_after_import": {"xoption": "int_max_str_digits=640", "code_reads_no_limit": "after_import"},
}


def _guard_scenarios():
    """Interni della libreria standard cambiati, scritti sul sorgente di `html.parser` di questo interprete (None dove
    la variante non si applica), e due controlli: la libreria com'è e il ripiego di SEC-48."""
    spec = importlib.util.find_spec("html.parser")
    source = spec.loader.get_source("html.parser") if spec is not None and spec.loader is not None else None
    if source is None:
        return dict.fromkeys(_GUARD_VARIANTS + _GUARD_CONTROLS)
    attribute_decoder = "_unescape_attrvalue" in source   # i valori di attributo decodificati da una funzione a parte
    imported = "from html import unescape\n"
    text = "self.handle_data(unescape(rawdata"
    variants = {
        "goahead_renamed": [("goahead", "goahead_next")],
        "parse_starttag_renamed": [("parse_starttag", "parse_starttag_next")],
        "text_decoded_under_another_name": [(imported, imported + "decode_text = unescape\n"),
                                            (text, "self.handle_data(decode_text(rawdata")],
        "text_decoded_through_the_html_module": [(imported, imported + "import html as html_module\n"),
                                                 (text, "self.handle_data(html_module.unescape(rawdata")],
        "attribute_decoder_renamed": (
            [("_unescape_attrvalue", "_decode_attrvalue")] if attribute_decoder else
            [(imported, imported + "\n\ndef _decode_attrvalue(s):\n    return unescape(s)\n"),
             ("attrvalue = unescape(attrvalue)", "attrvalue = _decode_attrvalue(attrvalue)")]),
        "attribute_decoder_with_another_unescape": (
            [(imported, "from html import unescape as html_unescape\n\n\n"
                        "def unescape(s):\n    return html_unescape(s)\n")] if attribute_decoder else None),
        "unchanged": [],
        "sec48_fallback": [("locatetagend", "locatetagend_next")],
    }
    return {name: None if replacements is None else {"guard": True, "sources": {"html.parser": replacements}}
            for name, replacements in variants.items()}


_GUARD_VARIANTS = ["goahead_renamed", "parse_starttag_renamed", "text_decoded_under_another_name",
                   "text_decoded_through_the_html_module", "attribute_decoder_renamed",
                   "attribute_decoder_with_another_unescape"]
_GUARD_CONTROLS = ["unchanged", "sec48_fallback"]
_GUARD_SCENARIOS = _guard_scenarios()

_SCENARIO_SOURCE = r'''
import importlib.util, json, logging, sys
root, tests, scenario = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
sys.path[:0] = [root, tests]
warnings = []

class Warnings(logging.Handler):
    def emit(self, record):
        warnings.append([record.levelname, record.name, record.getMessage()])

logging.getLogger().addHandler(Warnings(logging.WARNING))
for name, replacements in scenario.get("sources", {}).items():
    spec = importlib.util.find_spec(name)
    source = spec.loader.get_source(name)
    if source is None:
        raise SystemExit("sorgente di %s non disponibile: lo scenario non si può costruire" % name)
    changed = source
    for old, new in replacements:
        if old not in changed:
            raise SystemExit("scenario non applicabile: %r non è in %s" % (old, name))
        changed = changed.replace(old, new)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(changed, spec.origin, "exec"), module.__dict__)
    if name == "html.parser":
        sys.modules["html"].parser = module
reads_no_limit = scenario.get("code_reads_no_limit")
if reads_no_limit == "from_import":
    sys.get_int_max_str_digits = lambda: 0
import shared.utils
if scenario.get("runtime_limit") is not None:
    sys.set_int_max_str_digits(scenario["runtime_limit"])
if reads_no_limit == "after_import":
    sys.get_int_max_str_digits = lambda: 0
import test_html_charref_digits_sec50 as sec50
if scenario.get("guard"):
    report = sec50._guard_report()
elif reads_no_limit:
    report = sec50._conversion_report()
else:
    report = sec50._scenario_report()
report["warnings"] = warnings
print(json.dumps(report, ensure_ascii=False, default=repr))
'''

_SCENARIO_TIMEOUT_S = 120


@pytest.fixture(scope="module")
def scenario_reports():
    return _run_scenarios({**_FALLBACK_SCENARIOS, **_LIMIT_SCENARIOS, **_CONVERSION_SCENARIOS})


@pytest.fixture(scope="module")
def guard_reports():
    return _run_scenarios({name: scenario for name, scenario in _GUARD_SCENARIOS.items() if scenario is not None})


def _run_scenarios(scenarios):
    """Un interprete separato per scenario, tutti insieme."""
    procs = {}
    try:
        for name, scenario in scenarios.items():
            options = ["-X", scenario["xoption"]] if "xoption" in scenario else []
            command = [sys.executable, "-I", "-B", *options, "-c", _SCENARIO_SOURCE, str(_ROOT), str(_ROOT / "tests"),
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


def _report(scenario_reports, scenario):
    code, out, err = scenario_reports[scenario]
    assert code == 0, f"«{scenario}»: l'interprete è terminato con {code}: {err[-1500:]}"
    report = json.loads(out.strip().splitlines()[-1])
    assert report["documents"] > 100
    return report


class TestOtherConfigurations:
    @pytest.mark.parametrize("scenario", list(_FALLBACK_SCENARIOS))
    def test_results_are_those_of_the_unlimited_parser_with_the_fallback_parser(self, scenario_reports, scenario):
        report = _report(scenario_reports, scenario)

        assert report["fallback"] is not None, f"«{scenario}»: il collector non è passato al parser standard"
        assert report["raising_with_the_process_limit"] > 0
        assert not report["differences"], (
            f"«{scenario}» (ripiego: {report['fallback']!r}): risultati diversi dalla libreria standard senza limite: "
            f"{report['differences']}")

    @pytest.mark.parametrize("scenario", list(_LIMIT_SCENARIOS))
    def test_results_are_those_of_the_unlimited_parser_with_another_process_limit(self, scenario_reports, scenario):
        report = _report(scenario_reports, scenario)

        assert report["limit"] == _LIMIT_SCENARIOS[scenario]["expected_limit"]
        assert report["fallback"] is None
        # con un limite, il corpus ha riferimenti che il parser standard rifiuta; senza, nessuno
        assert (report["raising_with_the_process_limit"] > 0) == (report["limit"] != 0)
        assert not report["differences"], (
            f"«{scenario}» (limite {report['limit']}): risultati diversi dalla libreria standard senza limite: "
            f"{report['differences']}")


class TestConversionWorkDoesNotGrowWithTheDigits:
    @pytest.mark.parametrize("scenario", list(_CONVERSION_SCENARIOS))
    def test_no_conversion_gets_the_digits_of_a_whole_reference_even_without_a_process_limit(self, scenario_reports,
                                                                                            scenario):
        """Contesti, soglia, cifre significative, esadecimali, testo misto, documenti a caso e pagine grandi quanto il
        tetto dello scaricamento, col riferimento lungo quasi quanto la pagina: con un'unica conversione delle cifre
        intere, che senza limite costerebbe un tempo più che lineare nelle cifre, l'interprete a 640 solleva."""
        report = _report(scenario_reports, scenario)

        assert report["interpreter_limit"] == 640 and report["limit_read_by_the_code"] == 0, report
        assert report["fallback"] is None
        assert report["raising_with_the_interpreter_limit"] > 0
        assert not report["failed"], (
            f"«{scenario}»: {report['failed']} letture o analisi falliscono quando il codice legge che il processo non "
            f"ha limite: una conversione riceve più di 640 cifre: {report['failures']}")


class TestTheReductionIsInstalledOnlyOnTheExpectedInternals:
    def test_the_reduction_is_active_on_this_interpreter(self):
        """Sugli interpreti dei test gli interni sono quelli attesi: un ripiego qui vuol dire che in produzione le
        pagine con riferimenti lunghi tornano a non essere analizzate."""
        reason = _charref_fallback()

        assert reason is None, f"riduzione dei riferimenti lunghi spenta su questo interprete: {reason}"

    @pytest.mark.parametrize("control", _GUARD_CONTROLS)
    def test_the_reduction_is_active_with_the_standard_library_and_with_the_fallback_parser(self, guard_reports,
                                                                                         control):
        report = _report(guard_reports, control)

        assert report["charref_fallback"] is None, f"«{control}»: riduzione spenta: {report['charref_fallback']}"
        assert (report["fallback"] is not None) == (control == "sec48_fallback"), report["fallback"]
        assert not report["differences"], f"«{control}»: pagine leggibili diverse: {report['differences']}"

    @pytest.mark.parametrize("variant", _GUARD_VARIANTS)
    def test_changed_internals_leave_the_standard_methods_with_a_warning(self, guard_reports, variant):
        """L'import del codice riesce, il motivo è in `_CHARREF_FALLBACK` e in un WARNING, le pagine leggibili danno
        i risultati del parser standard della libreria cambiata, e restano tutti i metodi standard: nessun metodo
        ridotto in `_TagCollector`, nemmeno quando solo `parse_starttag` non passa i controlli (`goahead` li passa nelle
        varianti `parse_starttag_renamed` e `attribute_decoder_renamed`), e le pagine coi riferimenti lunghi danno
        l'esito del parser standard, errore compreso."""
        if _GUARD_SCENARIOS[variant] is None:
            pytest.skip("variante non applicabile alla libreria standard di questo interprete")
        report = _report(guard_reports, variant)
        reason = report["charref_fallback"]

        assert isinstance(reason, str) and reason and reason != _NO_CHARREF_FALLBACK, (
            f"«{variant}»: `_CHARREF_FALLBACK` vale {reason!r}")
        # il WARNING del ripiego di SEC-48, che alcune varianti provocano, non conta
        sec48 = report["fallback"]
        own = [message for level, _, message in report["warnings"]
               if level == "WARNING" and reason in message and not (sec48 and sec48 in message)]
        assert own, f"«{variant}»: nessun WARNING col motivo {reason!r}: {report['warnings']}"
        assert not report["differences"], (
            f"«{variant}»: pagine leggibili diverse dal parser standard: {report['differences']}")
        assert report["reduced_methods"] == [], (
            f"«{variant}»: metodi ridotti in `_TagCollector` accanto a quelli standard: {report['reduced_methods']}")
        assert not report["outcome_differences"], (
            f"«{variant}»: esito diverso dal parser standard: {report['outcome_differences']}")


# ── Nessun cambiamento per tutto il processo ──────────────────────────────────────────────────

_PROCESS_SOURCE = r'''
import json, sys
sys.path[:0] = [sys.argv[1]]
pages = json.loads(sys.stdin.read())
limit = sys.get_int_max_str_digits()
calls = []
stock_set = sys.set_int_max_str_digits

def recording_set(value):
    calls.append(value)
    return stock_set(value)

sys.set_int_max_str_digits = recording_set
import _markupbase
import html
import html.parser
modules = {name: sys.modules[name] for name in ("html", "html.parser", "_markupbase")}

def snapshot():
    held = {}
    for label, namespace in (("html", vars(html)), ("html.parser", vars(html.parser)),
                             ("_markupbase", vars(_markupbase)), ("HTMLParser", vars(html.parser.HTMLParser)),
                             ("ParserBase", vars(_markupbase.ParserBase))):
        for name, value in namespace.items():
            if name != "__warningregistry__":
                held[label + "." + name] = value
    return held

before = snapshot()
import shared.utils as utils
after_import = sys.get_int_max_str_digits()
raised = 0
for page in pages:
    try:
        utils.detect_hidden_elements(page, self_domain="sito.example")
    except ValueError:
        raised += 1
after = snapshot()
changed = sorted(k for k in set(before) | set(after) if k not in before or k not in after or before[k] is not after[k])
print(json.dumps({"limit": limit, "after_import": after_import, "after_use": sys.get_int_max_str_digits(),
                  "calls": calls, "raised": raised, "changed": changed,
                  "same_modules": sorted(n for n, m in modules.items() if sys.modules.get(n) is m)}))
'''


class TestNoProcessWideChange:
    def test_importing_and_using_the_analysis_changes_nothing_process_wide(self):
        """In un interprete pulito: il codice non chiama `sys.set_int_max_str_digits`, il limite resta quello di
        partenza dopo l'import e dopo l'analisi di pagine con riferimenti lunghi, e ogni nome di `html`,
        `html.parser`, `_markupbase`, `HTMLParser` e `ParserBase` è lo stesso oggetto di prima dell'import."""
        pages = [_HTTP_PAGES[name] for name in ("text_with_semicolon", "attribute_of_a_collected_img", "title",
                                                "tail_unclosed_textarea", "leading_zeros_then_65")]
        proc = subprocess.run([sys.executable, "-I", "-B", "-c", _PROCESS_SOURCE, str(_ROOT)], cwd=str(_ROOT),
                              input=json.dumps(pages), capture_output=True, text=True, timeout=120, check=False)
        assert proc.returncode == 0, proc.stderr[-1500:]
        report = json.loads(proc.stdout.strip().splitlines()[-1])

        assert report["calls"] == [], f"il codice imposta il limite di `int()` del processo: {report['calls']}"
        assert report["after_import"] == report["after_use"] == report["limit"], report
        assert report["same_modules"] == ["_markupbase", "html", "html.parser"], report
        assert not report["changed"], f"il codice sostituisce nomi della libreria standard: {report['changed']}"

    def test_the_process_limit_holds_while_the_parser_runs(self):
        """Ogni evento del parser, durante l'analisi di pagine con riferimenti lunghi, vede il limite del processo:
        il limite non viene tolto nemmeno per la durata del parsing, che altri thread vedrebbero."""
        seen = []

        class Watch(utils._TagCollector):
            def handle_starttag(self, tag, attrs):
                seen.append(sys.get_int_max_str_digits())
                super().handle_starttag(tag, attrs)

            def handle_endtag(self, tag):
                seen.append(sys.get_int_max_str_digits())
                super().handle_endtag(tag)

            def handle_data(self, data):
                seen.append(sys.get_int_max_str_digits())
                super().handle_data(data)

        limit = sys.get_int_max_str_digits()
        original = utils._TagCollector
        utils._TagCollector = Watch
        try:
            for name in ("text_with_semicolon", "attribute_of_a_collected_form", "title", "tail_unclosed_textarea"):
                with contextlib.suppress(ValueError):   # il difetto stesso è provato dagli altri test
                    utils.detect_hidden_elements(_HTTP_PAGES[name], self_domain=_SITE)
        finally:
            utils._TagCollector = original

        assert seen, "l'analisi non costruisce il parser con `shared.utils._TagCollector`"
        assert set(seen) == {limit}, f"limite visto durante il parsing: {sorted(set(seen))}, del processo {limit}"


# ── Pagine che la libreria standard legge senza errore ────────────────────────────────────────

class TestReadablePagesAreUnchanged:
    def test_targeted_pages_give_the_results_of_the_standard_parser_with_the_process_limit(self):
        """Pagine vere, cifre lunghe dove il parser non decodifica, riferimenti fino al limite, cifre non ASCII dopo
        `&#`: stessi tag, eventi e risultati del parser standard col limite del processo, che le legge senza errore."""
        readable = {name: html for name, html in _READABLE_CASES.items() if not _raises_with_the_process_limit(html)}
        found = _first_differences(readable.items(), lift_limit=False)

        assert sorted(readable) == sorted(_READABLE_CASES), (
            f"casi che il parser standard non legge: {sorted(set(_READABLE_CASES) - set(readable))}")
        assert not found, f"pagine leggibili diverse dal parser standard: {found}"

    def test_random_readable_documents_give_the_results_of_the_standard_parser_with_the_process_limit(self):
        readable = [(name, html) for name, html in _random_documents(51, 240)
                    if not _raises_with_the_process_limit(html)]
        found = _first_differences(readable, lift_limit=False)

        assert len(readable) >= 150, f"solo {len(readable)} documenti leggibili"
        assert not found, f"documenti leggibili diversi dal parser standard: {found}"
