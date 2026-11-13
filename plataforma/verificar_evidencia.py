#!/usr/bin/env python3
"""Verify a run's evidence end to end, and optionally export the deliverables to entrega/.

Checks:
1. Audit log hash chain (any edited, deleted or reordered line breaks it).
2. Each case's seal (SHA-256 over the evidence and analysis the judge saw).
3. Each case's seal matches the seal written in the audit log when the case was created.
4. Each stored capture still hashes to the SHA-256 recorded in its evidence.
5. Each judge decision signature (HMAC with the judge's demo key) over case id + seal.

Usage:
  python3 plataforma/verificar_evidencia.py <run dir> [--juzgados datos/juzgados.json] [--exportar entrega/]
"""
import argparse
import hashlib
import hmac
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from motor import calcular_sello, verificar_auditoria  # noqa: E402


def verificar(run: Path, juzgados: Path) -> dict:
    out = {"auditoria": None, "expedientes": [], "errores": []}
    ok, msg = verificar_auditoria(run / "auditoria.jsonl")
    out["auditoria"] = {"integra": ok, "detalle": msg}
    if not ok:
        out["errores"].append(msg)
    sellos_log = {}
    for linea in open(run / "auditoria.jsonl", encoding="utf-8"):
        e = json.loads(linea)
        if e["evento"] == "expediente_creado":
            sellos_log[e["datos"]["expediente"]] = e["datos"]["sello"]
    claves = {}
    if juzgados.exists():
        j = json.loads(juzgados.read_text(encoding="utf-8"))
        claves = {x["id"]: x["clave_firma_demo"] for jz in j["juzgados"] for x in jz["jueces"]}
    datos = json.loads((run / "expedientes.json").read_text(encoding="utf-8"))
    for x in datos["expedientes"]:
        r = {"id": x["id"], "sello_ok": calcular_sello(x) == x["sello"],
             "sello_en_auditoria": sellos_log.get(x["id"]) == x["sello"], "capturas_ok": True, "firma_ok": None}
        for ev in x["evidencia"]:
            h = ev.get("sha256_captura")
            if h:
                arch = next((run / "capturas").glob(h + ".*"), None)
                if arch is None or hashlib.sha256(arch.read_bytes()).hexdigest() != h:
                    r["capturas_ok"] = False
        d = x.get("decision")
        if d and d["juez_id"] in claves:
            msg = f"DECISION|{x['id']}|{x['sello']}|{'APRUEBA' if d['aprueba'] else 'RECHAZA'}"
            esperada = hmac.new(claves[d["juez_id"]].encode(), msg.encode(), hashlib.sha256).hexdigest()
            r["firma_ok"] = hmac.compare_digest(esperada, d["firma_decision"])
        for k in ("sello_ok", "sello_en_auditoria", "capturas_ok"):
            if not r[k]:
                out["errores"].append(f"{x['id']}: {k} falló")
        if r["firma_ok"] is False:
            out["errores"].append(f"{x['id']}: firma del juez inválida")
        out["expedientes"].append(r)
    return out


def elegir_ejemplo(datos: dict) -> dict:
    """The most complete approved case: live detection, most evidence, orders to every provider."""
    aprobados = [x for x in datos["expedientes"] if x["estado"] == "aprobado"] or datos["expedientes"]
    return max(aprobados, key=lambda x: (x.get("tipo") != "preventivo", len({o for o in x["ordenes"]}),
                                         len(x["evidencia"])))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--juzgados", type=Path, default=Path(__file__).resolve().parent.parent / "datos" / "juzgados.json")
    ap.add_argument("--exportar", type=Path)
    a = ap.parse_args()
    res = verificar(a.run, a.juzgados)
    n = len(res["expedientes"])
    print(f"Auditoría: {res['auditoria']['detalle']}")
    print(f"Expedientes verificados: {n} · sellos ok {sum(r['sello_ok'] for r in res['expedientes'])} · "
          f"sellos = auditoría {sum(r['sello_en_auditoria'] for r in res['expedientes'])} · "
          f"capturas ok {sum(r['capturas_ok'] for r in res['expedientes'])} · "
          f"firmas ok {sum(1 for r in res['expedientes'] if r['firma_ok'])}")
    print("RESULTADO:", "ÍNTEGRO" if not res["errores"] else "ALTERADO → " + "; ".join(res["errores"][:10]))
    if a.exportar:
        dst = a.exportar
        dst.mkdir(parents=True, exist_ok=True)
        datos = json.loads((a.run / "expedientes.json").read_text(encoding="utf-8"))
        ej = elegir_ejemplo(datos)
        (dst / f"expediente_{ej['id']}.json").write_text(json.dumps(ej, ensure_ascii=False, indent=2), encoding="utf-8")
        shutil.copy(a.run / "auditoria.jsonl", dst / "auditoria.jsonl")
        shutil.copy(a.run / "expedientes.json", dst / "expedientes_todos.json")
        if (a.run / "registro.jsonl").exists():
            shutil.copy(a.run / "registro.jsonl", dst / "registro_simulador.jsonl")
        cap = dst / "capturas"
        cap.mkdir(exist_ok=True)
        for ev in ej["evidencia"]:
            h = ev.get("sha256_captura")
            src = next((a.run / "capturas").glob(f"{h}.*"), None) if h else None
            if src:
                shutil.copy(src, cap / src.name)
        (dst / "verificacion.json").write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Exportado a {dst}: expediente_{ej['id']}.json, auditoria.jsonl, expedientes_todos.json, verificacion.json")
    sys.exit(0 if not res["errores"] else 1)


if __name__ == "__main__":
    main()
