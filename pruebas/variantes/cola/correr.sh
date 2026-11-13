#!/usr/bin/env bash
# Ronda de la variante "cola del juez": práctica (18600) y estrés (18650) en paralelo.
set -u
B=$HOME/dev/argentina-space/bloqueo-federal
V=$B/pruebas/variantes/cola
export MOTOR=$V/motor.py
specs=("ref_paralelo_j1:--juez-auto 1")
for S in 0.5 1 2; do
  specs+=("S${S}_fifo:--juez-serial $S --cola fifo"
          "S${S}_confirm:--juez-serial $S --cola confirmados"
          "S${S}_audiencia:--juez-serial $S --cola audiencia"
          "S${S}_fifo_lote:--juez-serial $S --cola fifo --lote"
          "S${S}_audien_lote:--juez-serial $S --cola audiencia --lote")
done
CORRIDAS=$V/corridas/practica PUERTO_BASE=18600 $B/pruebas/comparar.sh 30 "${specs[@]}" > $V/practica.txt 2>&1 &
CORRIDAS=$V/corridas/estres PUERTO_BASE=18650 ESCENARIO=$B/pruebas/estres/escenario_estres.json \
  VERDAD=$B/pruebas/estres/verdad_estres.json $B/pruebas/comparar.sh 30 "${specs[@]}" > $V/estres.txt 2>&1 &
wait
echo HECHO > $V/hecho.txt
