#!/usr/bin/env python3
"""TEST ONLY: a scripted judge that uses the web panel's HTTP API like a person would.

Logs in as both demo judges; whoever is on duty reviews the first batch in the queue, waiting
`--demora` real seconds per batch, and ratifies framework orders at the shift change.
"""
import argparse
import http.cookiejar
import json
import time
import urllib.request

ap = argparse.ArgumentParser()
ap.add_argument("--panel", default="http://localhost:8090")
ap.add_argument("--demora", type=float, default=3.0)
args = ap.parse_args()

sesiones = {}
for usuario, clave in [("laura", "laura2026"), ("martin", "martin2026")]:
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    req = urllib.request.Request(args.panel + "/api/login", data=json.dumps({"usuario": usuario, "clave": clave}).encode(),
                                 headers={"Content-Type": "application/json"})
    op.open(req).read()
    sesiones[usuario] = op


def llamar(op, ruta, cuerpo=None):
    data = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(args.panel + ruta, data=data, headers={"Content-Type": "application/json"})
    return json.loads(op.open(req, timeout=10).read())


while True:
    try:
        hizo = False
        for usuario, op in sesiones.items():
            s = llamar(op, "/api/estado")
            if s["minuto"] >= s["fin_min"] + 5:
                raise SystemExit
            if not s["puede_firmar"]:
                continue
            if s["ratificar"]:
                time.sleep(args.demora)
                print(usuario, "ratifica", llamar(op, "/api/ratificar", {}), flush=True)
                hizo = True
            elif s["cola"]:
                ids = [x["id"] for x in s["cola"][0]["items"]]
                time.sleep(args.demora)
                r = llamar(op, "/api/decidir", {"aprobar": ids})
                print(f"min {s['minuto']:.1f} {usuario} aprueba {ids}: {[x[1] for x in r['resultados']]}", flush=True)
                hizo = True
        if not hizo:
            time.sleep(0.3)
    except SystemExit:
        break
    except Exception as e:  # keep going; the panel may be busy
        print("error", e, flush=True)
        time.sleep(1)
