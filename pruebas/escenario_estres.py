#!/usr/bin/env python3
"""Build a 'stress' scenario + truth from the practice one: renamed sites/IPs, shifted times, extra traps.

Used only to check that the platform generalizes; it never reads the truth while running.
"""
import json
import sys
from pathlib import Path

desafio = Path(sys.argv[1])
salida = Path(sys.argv[2])
esc = json.loads((desafio / "datos" / "escenario_practica.json").read_text())
ver = json.loads((desafio / "evaluacion" / "verdad_practica.json").read_text())

RENOMBRES = {
    "pelotaya.test": "canchalibre.test", "s1.": "edge4.", "s2.": "edge5.", "s3.": "edge6.",
    "s1-respaldo.": "edge4-backup.", "espejo.": "mirror.",
    "golazo-libre.test": "golcito.test", "verpartido-hd.test": "mirapartido.test",
    "tribuna-pirata.test": "hinchada-tv.test", "x9.": "n21.", "x10.": "n22.",
    "resumenes-deportivos.test": "highlights-ar.test",
}
IPS = {"203.0.113.10": "203.0.113.110", "203.0.113.11": "203.0.113.111", "198.51.100.77": "198.51.100.177",
       "198.51.100.20": "198.51.100.120", "192.0.2.50": "192.0.2.150", "203.0.113.40": "203.0.113.140",
       "203.0.113.41": "203.0.113.141", "198.51.100.90": "198.51.100.190", "192.0.2.10": "192.0.2.10"}
DESPLAZAR = 1.5  # minutes


def ren(s: str) -> str:
    # longest keys first so 's1-respaldo.' wins over 's1.'
    for k in sorted(RENOMBRES, key=len, reverse=True):
        if k in s:
            s = s.replace(k, RENOMBRES[k])
    for k, v in IPS.items():
        s = s.replace(k, v)
    return s


def transformar(obj):
    if isinstance(obj, dict):
        return {ren(k) if isinstance(k, str) else k: transformar(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [transformar(x) for x in obj]
    if isinstance(obj, str):
        return ren(obj)
    return obj


esc2 = transformar(esc)
ver2 = transformar(ver)
esc2["id"] = ver2["escenario_id"] = "estres-01"
for d in esc2["detecciones"]:
    d["minuto"] = round(d["minuto"] + DESPLAZAR, 2)
    d["captura"]["capturada_min"] = d["minuto"]
for s in ver2["streams"]:
    for f in s["fases"]:
        f["desde_min"] += DESPLAZAR
        f["hasta_min"] = min(f["hasta_min"] + DESPLAZAR, 105) if f["hasta_min"] < 105 else 105

# Trampa 1: detección sin marca de agua en un sitio nuevo (no debe bloquearse).
base = dict(esc2["detecciones"][0])
esc2["detecciones"].append(dict(base, id="D-9001", minuto=30.0, pagina="https://otrodeporte.test/vivo",
                                host_stream="cdn.otrodeporte.test", ip_servidor="203.0.113.200",
                                marca_de_agua_extraida=None, captura=dict(base["captura"], capturada_min=30.0)))
esc2["dns_pasivo"]["203.0.113.200"] = ["cdn.otrodeporte.test"]
esc2["ip_asn"]["203.0.113.200"] = 64600
ver2["streams"].append({"id": "sin-marca", "clase": "falso_positivo",
                        "fases": [{"host": "cdn.otrodeporte.test", "ip": "203.0.113.200", "desde_min": 30.0, "hasta_min": 105}]})

# Trampa 2: señal del licenciatario retransmitida en un dominio pirata (sí debe bloquearse).
lic = next(d for d in esc2["detecciones"] if "canalnorte" in d["host_stream"])
esc2["detecciones"].append(dict(lic, id="D-9002", minuto=40.0, pagina="https://reenvio-norte.test/vivo",
                                host_stream="live.reenvio-norte.test", ip_servidor="203.0.113.201",
                                captura=dict(lic["captura"], capturada_min=40.0)))
esc2["dns_pasivo"]["203.0.113.201"] = ["live.reenvio-norte.test"]
esc2["ip_asn"]["203.0.113.201"] = 64600
ver2["dominios_piratas"].append("live.reenvio-norte.test")
ver2["streams"].append({"id": "reenvio-lic", "clase": "pirata",
                        "fases": [{"host": "live.reenvio-norte.test", "ip": "203.0.113.201", "desde_min": 40.0,
                                   "hasta_min": 105, "bloqueo_recomendado": "ip"}]})

esc2["detecciones"].sort(key=lambda d: d["minuto"])
salida.mkdir(parents=True, exist_ok=True)
(salida / "escenario_estres.json").write_text(json.dumps(esc2, ensure_ascii=False, indent=2))
(salida / "verdad_estres.json").write_text(json.dumps(ver2, ensure_ascii=False, indent=2))
print("ok", len(esc2["detecciones"]), "detecciones")
