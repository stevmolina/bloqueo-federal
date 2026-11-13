#!/usr/bin/env bash
# Corre un partido de práctica por estrategia, en paralelo, y resume el puntaje de verificar.py.
# Uso: pruebas/comparar.sh <acelerar> "<nombre>:<flags>" ...
set -u
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
DESAFIO="${DESAFIO:-$RAIZ/../desafio-futbol}"
ACEL="$1"; shift
PUERTO=${PUERTO_BASE:-18200}
for spec in "$@"; do
  nombre="${spec%%:*}"; flags="${spec#*:}"
  dir="${CORRIDAS:-$RAIZ/pruebas/corridas}/$nombre"; rm -rf "$dir"; mkdir -p "$dir"
  PUERTO=$((PUERTO+1))
  (
    timeout 900 python3 "$DESAFIO/simulador/servidor.py" --escenario "${ESCENARIO:-$DESAFIO/datos/escenario_practica.json}" \
      --acelerar "$ACEL" --puerto "$PUERTO" --log "$dir/registro.jsonl" > "$dir/sim.out" 2>&1 &
    SIM=$!
    sleep 1
    python3 "${MOTOR:-$RAIZ/plataforma/motor.py}" --servidor "http://localhost:$PUERTO" --juzgados "$DESAFIO/datos/juzgados.json" \
      --salida "$dir" $flags > "$dir/plataforma.out" 2>&1
    sleep 1; kill $SIM 2>/dev/null
    python3 "$DESAFIO/evaluacion/verificar.py" --log "$dir/registro.jsonl" --escenario "${ESCENARIO:-$DESAFIO/datos/escenario_practica.json}" --verdad "${VERDAD:-$DESAFIO/evaluacion/verdad_practica.json}" > "$dir/puntaje.txt" 2>&1
    python3 "$DESAFIO/evaluacion/verificar.py" --log "$dir/registro.jsonl" --escenario "${ESCENARIO:-$DESAFIO/datos/escenario_practica.json}" --verdad "${VERDAD:-$DESAFIO/evaluacion/verdad_practica.json}" --json > "$dir/puntaje.json" 2>&1
  ) &
done
wait
python3 - "${CORRIDAS:-$RAIZ/pruebas/corridas}" "$@" <<'EOF'
import json, sys, pathlib
base = pathlib.Path(sys.argv[1])
print(f"{'estrategia':28} {'fases':6} {'visib%':>7} {'colat':>5} {'falsos':>6} {'ipPost':>6} {'rechaz':>6} {'fallid':>6} {'recl':>4} {'fueraT':>6}  1er bloqueo por fase (min)")
for spec in sys.argv[2:]:
    n = spec.split(":")[0]
    try:
        r = json.loads((base / n / "puntaje.json").read_text())
    except Exception as e:
        print(n, "ERROR", e); continue
    s = r["resumen"]
    primeros = " ".join("-" if f["primer_bloqueo_min"] is None else f"{f['primer_bloqueo_min']:.1f}" for f in r["fases"])
    print(f"{n:28} {s['fases_piratas_bloqueadas']:6} {s['visibilidad_residual_promedio_pct']:>7} {s['bloqueos_con_dano_colateral']:>5} "
          f"{s['bloqueos_falsos_positivos']:>6} {str(s['bloqueos_ip_activos_post_partido']):>6} {s['ordenes_rechazadas']:>6} "
          f"{s['ordenes_fallidas']:>6} {s['reclamos']:>4} {s['ordenes_firmadas_fuera_de_turno']:>6}  {primeros}")
EOF
