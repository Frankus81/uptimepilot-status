#!/usr/bin/env python3
"""cert_watch.py -- TLS-certificaat-expiry- + terugval-bewaking (blok
2026-08-07/S10.5, uitgebreid in S10.7, regime uptimepilot).

Meet per endpoint in `cert-watch.json` het daadwerkelijk gepresenteerde
certificaat via `openssl s_client` (met `-starttls` waar nodig) --
geen aanname uit een configbestand, alleen wat er echt over de lijn
komt. Endpoints worden intern uniek geïdentificeerd via `hostname:poort`
-- eenzelfde hostname mag op meerdere poorten voorkomen (bv.
mail.frankvos.nl zowel op 443/https als 993/imaps, twee losse,
betekenisvol verschillende metingen sinds S10.7).

Schrijft bij ELKE run (ook geslaagd, ook mislukt):

  - cert-watch-results.json  (machineleesbaar, laatste meting per
    endpoint, incl. serienummer -- dient ook als BASELINE voor de
    volgende run se terugvaldetectie)
  - cert-watch-heartbeat.md  (mens-leesbaar: poort, protocol, dagen-
    tot-verval, serienummer per endpoint -- het bewijs dat de
    bewaking zelf nog leeft)

Twee onafhankelijke signalen (Deel 2, S10.7):

  1. Verval nadert: drempels uit `drempels_dagen` (dagen tot notAfter).
  2. Terugval: het serienummer wijzigt EN de nieuwe notAfter ligt niet
     later dan de vorige gemeten notAfter. Een normale renewal
     (serienummer wijzigt, notAfter gaat vooruit) is GEEN terugval en
     geeft geen melding -- anders leert dit mensen meldingen weg te
     klikken bij elke renewal.

Bij een probleem (drempel-overschrijding, terugval of meetfout): opent
of werkt een bestaand GitHub-issue bij (REST API, GH_PAT-token). Sluit
het issue weer zodra er geen problemen meer zijn. Een onbereikbare
host is een MEETFOUT, geen stille skip.

Exit-code 1 zodra er minstens één probleem is -- 0 als alles gemeten
kon worden, boven alle drempels blijft en geen terugval toont.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

CONFIG_PATH = "cert-watch.json"
RESULTS_PATH = "cert-watch-results.json"
HEARTBEAT_PATH = "cert-watch-heartbeat.md"

ISSUE_TITLE = "🔒 Certificaat-expiry-waarschuwing"
ISSUE_MARKER = "<!-- cert-watch-issue -->"

TOKEN = os.environ.get("GH_PAT") or os.environ.get("GITHUB_TOKEN")
REPO = os.environ.get("GITHUB_REPOSITORY", "Frankus81/uptimepilot-status")


def endpoint_id(hostname: str, port: int) -> str:
    return f"{hostname}:{port}"


def meet(host: str, port: int, starttls: str | None, timeout: int = 15) -> dict:
    """Eén endpoint meten. `ok: False` + `fout` bij elke afwijking van
    een schone, leesbare serial/notAfter-uitkomst -- nooit
    stilzwijgend overslaan."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host]
    if starttls:
        cmd += ["-starttls", starttls]
    try:
        s_client = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "fout": "timeout tijdens TLS-handshake"}
    except OSError as e:
        return {"ok": False, "fout": f"kon openssl niet starten: {e}"}

    if "BEGIN CERTIFICATE" not in s_client.stdout:
        detail = (s_client.stderr or s_client.stdout).strip()[:300]
        return {"ok": False, "fout": f"geen certificaat ontvangen (exit={s_client.returncode}): {detail}"}

    x509 = subprocess.run(
        ["openssl", "x509", "-noout", "-serial", "-enddate"],
        input=s_client.stdout, capture_output=True, text=True, timeout=timeout,
    )
    regels = {}
    for regel in x509.stdout.strip().splitlines():
        if "=" in regel:
            k, _, v = regel.partition("=")
            regels[k] = v

    if "notAfter" not in regels:
        return {"ok": False, "fout": f"kon notAfter niet uitlezen: {x509.stderr.strip()[:300]}"}
    if "serial" not in regels:
        return {"ok": False, "fout": f"kon serial niet uitlezen: {x509.stderr.strip()[:300]}"}

    raw = regels["notAfter"]
    try:
        dt = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except ValueError as e:
        return {"ok": False, "fout": f"onleesbare notAfter-waarde {raw!r}: {e}"}

    dagen = (dt - datetime.datetime.now(datetime.timezone.utc)).days
    return {"ok": True, "not_after": dt.isoformat(), "dagen_tot_verval": dagen, "serial": regels["serial"]}


def hoogste_overschreden_drempel(dagen: int, drempels: list[int]) -> int | None:
    overschreden = [d for d in drempels if dagen <= d]
    return min(overschreden) if overschreden else None


def terugval_check(vorige: dict | None, nieuw: dict) -> str | None:
    """Deel 2 (blok S10.7): een serienummerwijziging is normaal bij een
    renewal (notAfter gaat vooruit) -- alleen wanneer de nieuwe notAfter
    NIET later ligt dan de vorige is het een reële terugval (bv. een
    vhost-alias die sneuvelt en terugvalt op een ouder certificaat).
    Geen vorige/onbruikbare vorige meting -> geen conclusie, geen
    valse melding op de allereerste run van een endpoint."""
    if not vorige or not vorige.get("ok"):
        return None
    if vorige.get("serial") == nieuw.get("serial"):
        return None
    try:
        vorige_dt = datetime.datetime.fromisoformat(vorige["not_after"])
        nieuw_dt = datetime.datetime.fromisoformat(nieuw["not_after"])
    except (KeyError, ValueError):
        return None
    if nieuw_dt <= vorige_dt:
        return (
            f"serienummer gewijzigd ({vorige['serial']} → {nieuw['serial']}) maar notAfter "
            f"ging NIET vooruit ({vorige['not_after']} → {nieuw['not_after']}) — dit is geen "
            f"renewal maar een terugval"
        )
    return None  # normale renewal: serienummer + notAfter allebei vooruit, geen melding


def gh_api(method: str, path: str, payload: dict | None = None):
    if not TOKEN:
        raise RuntimeError("geen GH_PAT/GITHUB_TOKEN beschikbaar -- kan issue-API niet aanroepen")
    url = f"https://api.github.com{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "uptimepilot-cert-watch",
    })
    try:
        with urllib.request.urlopen(req) as resp:
            body = resp.read()
            return json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:500]
        raise RuntimeError(f"GitHub API {method} {path} -> {e.code}: {detail}") from e


def vind_open_issue() -> dict | None:
    issues = gh_api("GET", f"/repos/{REPO}/issues?state=open&per_page=100")
    for i in issues:
        if "pull_request" in i:
            continue
        if ISSUE_MARKER in (i.get("body") or ""):
            return i
    return None


def laad_vorige_resultaten() -> dict:
    """Baseline voor de terugvaldetectie: het resultatenbestand zoals
    het NA de vorige run gecommit is (checkout gebeurt vóór dit script
    draait). Ontbreekt het (allereerste run) -> lege baseline, geen
    endpoint heeft dan een vorige meting om tegen te vergelijken."""
    if not os.path.isfile(RESULTS_PATH):
        return {}
    try:
        data = json.load(open(RESULTS_PATH, encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data.get("resultaten", {})


def main() -> int:
    config = json.load(open(CONFIG_PATH, encoding="utf-8"))
    drempels = config.get("drempels_dagen", [21, 14, 7, 3])
    now = datetime.datetime.now(datetime.timezone.utc)
    vorige_resultaten = laad_vorige_resultaten()

    resultaten: dict[str, dict] = {}
    problemen: list[str] = []
    for h in config["hosts"]:
        eid = endpoint_id(h["hostname"], h.get("port", 443))
        r = meet(h["hostname"], h.get("port", 443), h.get("starttls"))
        r["hostname"] = h["hostname"]
        r["port"] = h.get("port", 443)
        r["protocol"] = h.get("protocol", "https")
        resultaten[eid] = r

        if not r["ok"]:
            problemen.append(f"- **{eid}** ({r['protocol']}): MEETFOUT — {r['fout']}")
            continue

        drempel = hoogste_overschreden_drempel(r["dagen_tot_verval"], drempels)
        r["drempel_overschreden"] = drempel
        if drempel is not None:
            problemen.append(
                f"- **{eid}** ({r['protocol']}): nog {r['dagen_tot_verval']} dagen tot verval "
                f"(drempel {drempel} overschreden, verloopt {r['not_after']})"
            )

        terugval = terugval_check(vorige_resultaten.get(eid), r)
        r["terugval"] = terugval
        if terugval:
            problemen.append(f"- **{eid}** ({r['protocol']}): TERUGVAL — {terugval}")

    json.dump(
        {"gemeten_op": now.isoformat(), "resultaten": resultaten},
        open(RESULTS_PATH, "w", encoding="utf-8"),
        indent=2, sort_keys=True, ensure_ascii=False,
    )
    with open(HEARTBEAT_PATH, "w", encoding="utf-8") as f:
        f.write("# Certificaat-expiry-heartbeat\n\n")
        f.write(
            "Deze regel bewijst dat de bewaking zelf leeft -- verandert deze meer dan "
            "twee dagen niet, is de bewaking zelf het probleem (zie blok 2026-08-07/S10.5).\n\n"
        )
        f.write(f"Laatste meting: **{now.isoformat()}**\n\n")
        f.write("| Endpoint | Poort | Protocol | Dagen tot verval | Serienummer | Status |\n|---|---|---|---|---|---|\n")
        for eid, r in resultaten.items():
            if r["ok"]:
                statussen = []
                if r.get("drempel_overschreden") is not None:
                    statussen.append(f"⚠ drempel {r['drempel_overschreden']} overschreden")
                if r.get("terugval"):
                    statussen.append("⚠ TERUGVAL")
                status = " / ".join(statussen) if statussen else "ok"
                f.write(f"| {r['hostname']} | {r['port']} | {r['protocol']} | {r['dagen_tot_verval']} | {r['serial']} | {status} |\n")
            else:
                f.write(f"| {r['hostname']} | {r['port']} | {r['protocol']} | — | — | MEETFOUT: {r['fout']} |\n")

    bestaand = vind_open_issue()
    if problemen:
        body = ISSUE_MARKER + "\n\n" + "\n".join(problemen) + f"\n\n_Laatste meting: {now.isoformat()}_"
        if bestaand:
            gh_api("PATCH", f"/repos/{REPO}/issues/{bestaand['number']}", {"body": body})
            print(f"issue #{bestaand['number']} bijgewerkt")
        else:
            nieuw = gh_api("POST", f"/repos/{REPO}/issues", {"title": ISSUE_TITLE, "body": body})
            print(f"nieuw issue geopend: #{nieuw['number']}")
        print("\n".join(problemen))
        return 1

    if bestaand:
        gh_api("PATCH", f"/repos/{REPO}/issues/{bestaand['number']}", {
            "state": "closed",
            "body": ISSUE_MARKER + f"\n\nHersteld — geen drempel-overschrijdingen of terugvallen meer.\n\n_Laatste meting: {now.isoformat()}_",
        })
        print(f"issue #{bestaand['number']} gesloten (hersteld)")
    print("alle endpoints OK: boven alle drempels, geen terugval")
    return 0


if __name__ == "__main__":
    sys.exit(main())
