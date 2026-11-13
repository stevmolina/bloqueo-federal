#!/usr/bin/env bash
# Ronda de la variante "cola del juez": práctica (18600) y estrés (18650) en paralelo.
set -u
B=$HOME/dev/argentina-space/bloqueo-federal
V=$B/pruebas/variantes/cola
export MOTOR=$V/motor.py
specs=()
for S in 1 2 3; do
  specs+=("S${S}_fifo:--juez-serial $S --cola fifo"
          "S${S}_confirm_lote:--juez-serial $S --cola confirmados --lote"
          "S${S}_audien_lote:--juez-serial $S --cola audiencia --lote"
          "S${S}_fifo_temp:--juez-serial $S --cola fifo --prediccion-temprana"
          "S${S}_audien_lote_temp:--juez-serial $S --cola audiencia --lote --prediccion-temprana")
done
CORRIDAS=$V/corridas/r2_practica PUERTO_BASE=18600 $B/pruebas/comparar.sh 30 "${specs[@]}" > $V/r2_practica.txt 2>&1 &
CORRIDAS=$V/corridas/r2_estres PUERTO_BASE=18650 ESCENARIO=$B/pruebas/estres/escenario_estres.json \
  VERDAD=$B/pruebas/estres/verdad_estres.json $B/pruebas/comparar.sh 30 "${specs[@]}" > $V/r2_estres.txt 2>&1 &
wait
echo HECHO > $V/hecho2.txt
