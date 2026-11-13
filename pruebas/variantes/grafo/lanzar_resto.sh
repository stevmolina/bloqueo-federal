#!/usr/bin/env bash
cd ~/dev/argentina-space/bloqueo-federal
V=$PWD/pruebas/variantes/grafo; E=$PWD/pruebas/estres
MOTOR=$V/motor.py CORRIDAS=$V/corridas PUERTO_BASE=18450 ESCENARIO=$E/escenario_estres.json VERDAD=$E/verdad_estres.json pruebas/comparar.sh 30 "S_grafo_j1:--juez-auto 1" "S_grafo_j3:--juez-auto 3" "S_grafoSinAdiv_j1:--juez-auto 1 --sin-adivinar" "S_grafoSinAdiv_j3:--juez-auto 3 --sin-adivinar" > $V/ronda_estres.txt 2>&1 &
CORRIDAS=$V/corridas_base PUERTO_BASE=18420 pruebas/comparar.sh 30 "P_base_j1:--juez-auto 1" "P_base_j3:--juez-auto 3" > $V/ronda_base_practica.txt 2>&1 &
CORRIDAS=$V/corridas_base PUERTO_BASE=18470 ESCENARIO=$E/escenario_estres.json VERDAD=$E/verdad_estres.json pruebas/comparar.sh 30 "S_base_j1:--juez-auto 1" "S_base_j3:--juez-auto 3" > $V/ronda_base_estres.txt 2>&1 &
wait
