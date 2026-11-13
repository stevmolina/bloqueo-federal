import json, sys, pathlib
base = pathlib.Path(sys.argv[1])
for d in sorted(base.iterdir()):
    try:
        r = json.loads((d / "puntaje.json").read_text()); m = json.loads((d / "metricas.json").read_text())
    except Exception as e:
        print(d.name, "ERR", e); continue
    s = r["resumen"]; lat = m["latencias_det_orden"]
    print(f"{d.name:14} vis={s['visibilidad_residual_promedio_pct']:>4} fases={s['fases_piratas_bloqueadas']} col={s['bloqueos_con_dano_colateral']} fp={s['bloqueos_falsos_positivos']} ipPost={s['bloqueos_ip_activos_post_partido']} rech={s['ordenes_rechazadas']} fall={s['ordenes_fallidas']} recib={s['ordenes_recibidas']} recl={s['reclamos']} fueraT={s['ordenes_firmadas_fuera_de_turno']}"
          f" | lat det->orden max={max(lat) if lat else None} mean={round(sum(lat)/len(lat),3) if lat else None} tick_med={m['tick_medio_s']} tick_max={round(m['tick_max_s'],3)} copias+={m['copias_extra']}")
    print("      fases:", " ".join(str(f["visibilidad_residual_pct"]) for f in r["fases"]))
