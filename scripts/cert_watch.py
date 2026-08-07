#!/usr/bin/env python3
"""cert_watch.py -- TLS-certificaat-expiry-bewaking (blok
2026-08-07/S10.5, regime uptimepilot).

Meet per host in `cert-watch.json` het daadwerkelijk gepresenteerde
certificaat via `openssl s_client` -- geen aanname uit een
configbestand, alleen wat er echt over de lijn komt. Schrijft bij
ELKE run (ook een geslaagde, ook een mislukte):

  - cert-watch-results.json  (machineleesbaar, laatste meting per host)
  - cert-watch-heartbeat.md  (mens-leesbaar, tijdstempel + dagen-tot-
    verval per host -- het bewijs dat de bewaking zelf nog leeft, zie
    de heartbeat-rationale in de bloktekst: stilte mag nooit gelezen
    worden als "in orde")

Bij een overschreden drempel: opent of werkt een bestaand GitHub-issue
bij (REST API, GH_PAT-token). Sluit het issue weer zodra de meting
weer boven de hoogste drempel komt. Een onbereikbare host is een
MEETFOUT, geen stille skip -- telt mee als probleem, verschijnt in het
issue en laat de workflow rood kleuren, exact zoals Deel 3 van de
bloktekst voorschrijft.

Exit-code 1 zodra er minstens één drempel-overschrijding of meetfout
is (zichtbaar-rood-principe uit de bloktekst) -- 0 als alles gemeten
kon worden en boven alle drempels blijft.
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


def meet(host: str, port: int, starttls: str | None, timeout: int = 15) -> dict:
    """Eén host meten. `ok: False` + `fout` bij elke afwijking van een
    schone, leesbare notAfter-waarde -- nooit stilzwijgend overslaan."""
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
        ["openssl", "x509", "-noout", "-enddate"],
        input=s_client.stdout, capture_output=True, text=True, timeout=timeout,
    )
    out = x509.stdout.strip()
    if not out.startswith("notAfter="):
        return {"ok": False, "fout": f"kon notAfter niet uitlezen: {x509.stderr.strip()[:300]}"}

    raw = out[len("notAfter="):]
    try:
        dt = datetime.datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except ValueError as e:
        return {"ok": False, "fout": f"onleesbare notAfter-waarde {raw!r}: {e}"}

    dagen = (dt - datetime.datetime.now(datetime.timezone.utc)).days
    return {"ok": True, "not_after": dt.isoformat(), "dagen_tot_verval": dagen}


def hoogste_overschreden_drempel(dagen: int, drempels: list[int]) -> int | None:
    overschreden = [d for d in drempels if dagen <= d]
    return min(overschreden) if overschreden else None


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


def main() -> int:
    config = json.load(open(CONFIG_PATH, encoding="utf-8"))
    drempels = config.get("drempels_dagen", [21, 14, 7, 3])
    now = datetime.datetime.now(datetime.timezone.utc)

    resultaten: dict[str, dict] = {}
    problemen: list[str] = []
    for h in config["hosts"]:
        r = meet(h["hostname"], h.get("port", 443), h.get("starttls"))
        resultaten[h["hostname"]] = r
        if not r["ok"]:
            problemen.append(f"- **{h['hostname']}**: MEETFOUT — {r['fout']}")
            continue
        drempel = hoogste_overschreden_drempel(r["dagen_tot_verval"], drempels)
        r["drempel_overschreden"] = drempel
        if drempel is not None:
            problemen.append(
                f"- **{h['hostname']}**: nog {r['dagen_tot_verval']} dagen tot verval "
                f"(drempel {drempel} overschreden, verloopt {r['not_after']})"
            )

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
        f.write("| Host | Dagen tot verval | notAfter | Status |\n|---|---|---|---|\n")
        for host, r in resultaten.items():
            if r["ok"]:
                if r.get("drempel_overschreden") is not None:
                    status = f"⚠ drempel {r['drempel_overschreden']} overschreden"
                else:
                    status = "ok"
                f.write(f"| {host} | {r['dagen_tot_verval']} | {r['not_after']} | {status} |\n")
            else:
                f.write(f"| {host} | — | — | MEETFOUT: {r['fout']} |\n")

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
            "body": ISSUE_MARKER + f"\n\nHersteld — alle certificaten weer boven de hoogste drempel.\n\n_Laatste meting: {now.isoformat()}_",
        })
        print(f"issue #{bestaand['number']} gesloten (hersteld)")
    print("alle certificaten OK, boven alle drempels")
    return 0


if __name__ == "__main__":
    sys.exit(main())
