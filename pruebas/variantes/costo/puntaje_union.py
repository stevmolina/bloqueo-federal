"""Re-score residual visibility with the UNION of each provider's block intervals (verificar.py sums them,
so overlapping duplicate/IP+domain orders are double-counted). Usage: puntaje_union.py <escenario> <verdad> <run dirs...>"""
import json, sys, pathlib
sys.path.insert(0, str(pathlib.Path.home() / "dev/argentina-space/desafio-futbol/evaluacion"))
import verificar as V
esc = json.load(open(sys.argv[1])); verdad = json.load(open(sys.argv[2]))
prov = json.load(open(pathlib.Path.home() / "dev/argentina-space/desafio-futbol/datos/proveedores.json"))
cli = {p["id"]: p["clientes"] for p in prov["proveedores"]}; tot = sum(cli.values())
for d in sys.argv[3:]:
    ev = V.cargar_log(pathlib.Path(d) / "registro.jsonl"); log_fin = ev[-1]["min"]
    ords = [o for o in V.reconstruir_ordenes(ev).values() if o["aplicada"] is not None]
    vis = []
    for s in verdad["streams"]:
        if s["clase"] != "pirata": continue
        for f in s["fases"]:
            a, b = f["desde_min"], min(f["hasta_min"], log_fin)
            if a >= log_fin: continue
            cub = 0.0
            for p in cli:
                iv = sorted((max(o["aplicada"], a), min(o["fin"] if o["fin"] is not None else b, b))
                            for o in ords if o["proveedor"] == p and V.afecta(o, f["ip"], f["host"]))
                tot_p, cur = 0.0, None
                for x, y in iv:
                    if y <= x: continue
                    if cur and x <= cur[1]: cur[1] = max(cur[1], y)
                    else:
                        if cur: tot_p += cur[1] - cur[0]
                        cur = [x, y]
                if cur: tot_p += cur[1] - cur[0]
                cub += cli[p] * tot_p
            vis.append(round(100 * (1 - cub / (tot * max(b - a, 1e-9))), 2))
    print(f"{pathlib.Path(d).name:16} union_vis={round(sum(vis)/len(vis),2):>5}  fases: {' '.join(map(str, vis))}")
