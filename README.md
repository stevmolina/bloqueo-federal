# Bloqueo Federal · Plataforma de órdenes de bloqueo en vivo

MVP para el **Desafío Fútbol** (track Streaming de QualyData, Hackathon Argentina Space 2026, Salta).

Durante el partido, la plataforma hace el circuito completo:

```
detección → expediente con evidencia sellada → juez de turno firma → orden a cada proveedor
         → confirmación y reintento → vencimiento al final → auditoría encadenada
```

Todo corre contra el simulador oficial. No se bloquea nada real.

## Cómo correrlo

Requisitos: Python 3.9+, sin dependencias externas. Clonar este repo junto al repo del desafío
(`desafio-futbol`).

```bash
# 1. Simulador oficial (otra terminal)
python3 ../desafio-futbol/simulador/servidor.py --escenario ../desafio-futbol/datos/escenario_practica.json --acelerar 6

# 2. Plataforma + panel del juez
python3 plataforma/motor.py --servidor http://localhost:8080 \
  --juzgados ../desafio-futbol/datos/juzgados.json --salida salida --web 8090

# 3. Abrir http://localhost:8090 e ingresar como juez de turno
#    Usuarios de DEMOSTRACIÓN: laura / laura2026 (jueza Laura, turno 1) · martin / martin2026 (juez Martín, turno 2)

# 4. Al terminar: puntaje oficial, verificación de evidencia y exportación a entrega/
python3 ../desafio-futbol/evaluacion/verificar.py --log salida/registro.jsonl   # si el simulador escribió ahí
python3 plataforma/verificar_evidencia.py salida --juzgados ../desafio-futbol/datos/juzgados.json --exportar entrega
```

Otras páginas del panel: `/transparencia` (registro público) y `/expediente/<id>` (vista imprimible
con verificación del sello).

## Qué hace, paso a paso

1. **Expediente.** Por cada detección verifica la marca de agua contra `GET /partido`. Descarta lo que
   no es la señal del partido (otra marca o ninguna) y al **licenciatario autorizado en sus dominios**.
   La señal del licenciatario en un dominio no autorizado sí se trata como pirata. Registra servidor
   (host, IP, ASN y organización), consulta DNS pasivo y guarda la captura con su SHA-256.
2. **Riesgo colateral.** Si la IP aloja otros sitios (o es CDN u hosting compartido, o no hay datos),
   **solo se pide bloqueo por dominio**. Si la IP es dedicada, se pide IP **y** dominio (respaldo), y
   también los otros dominios del mismo sitio en esa IP.
3. **Juez de turno.** Login con usuario y contraseña (hash PBKDF2). Cada juez ve la cola y firma solo
   durante su turno. Al cambio de turno, lo pendiente pasa al juez entrante, que ratifica las órdenes
   marco del turno anterior en un clic. La plataforma firma con la clave del juez **solo después** de
   su aprobación.
4. **Cola inteligente.** Primero los streams en vivo y después los preventivos. Un lote por sitio u
   operación: el juez ve cada servidor y puede destildar cualquiera antes de firmar. Aviso sonoro y
   notificación del navegador. Atajo **A** para aprobar el primer lote.
5. **Orden marco.** Si el juez de turno ya aprobó ese sitio o esa misma marca de agua filtrada, el
   servidor nuevo se incorpora a esa orden, firmada por ese mismo juez.
6. **Infraestructura vinculada (preventivo).** Al crear un expediente se consulta DNS pasivo por
   servidores hermanos del sitio (`s1`→`s2`, `espejo.`, `mirror.`, …). Se proponen al juez en el mismo
   lote como bloqueo **preventivo**. Nunca se incluye una IP compartida.
7. **Proveedores.** A cada proveedor se le envía el tipo de bloqueo que acepta. Se sigue el estado y se
   reenvía con un `orden_id` nuevo si falla. Si el juez que aprobó ya no está de turno, el reintento
   lo firma el entrante.
8. **Vencimiento.** Las órdenes vencen en el minuto final del partido (`vence_min`), así no quedan
   bloqueos por IP activos después.
9. **Reclamos (extra).** Ante un reclamo, se levanta la orden con firma judicial y, si era por IP, se
   reemplaza por un bloqueo por dominio.
10. **Auditoría.** Cada paso queda en `auditoria.jsonl` con el hash del anterior (cadena). Cambiar,
    borrar o reordenar una línea rompe la cadena. `verificar_evidencia.py` revisa la cadena, los sellos
    de los expedientes, las capturas y las firmas de las decisiones.

## Resultados en práctica (simulador oficial, x30)

Probamos varias estrategias con el verificador oficial y con un escenario de estrés propio (otros
dominios, IPs y tiempos, más trampas: detección sin marca y señal del licenciatario reenviada).
La plataforma no lee nunca las respuestas correctas.

| Estrategia | Fases bloqueadas | Visibilidad residual (oficial) | Sitios legítimos afectados |
|---|---|---|---|
| Cliente mínimo de ejemplo | 1 de 7 | 86,5 % | 0 |
| Solo IP | 7 de 7 | 6,0 % | 5 |
| Solo dominio | 7 de 7 | 3,3 % | 0 |
| **Esta plataforma** (juez 1 min por lote) | **7 de 7** | **0,9 %** | **0** |
| **Esta plataforma**, escenario de estrés | **8 de 8** | **0,8 %** | **0** |

En todas las corridas: 0 falsos positivos, 0 bloqueos por IP activos después del partido, 0 órdenes
firmadas fuera de turno, 0 órdenes rechazadas.

**Nota sobre la métrica.** `verificar.py` suma los minutos de todas las órdenes que cubren una fase en
un mismo proveedor y recorta al largo de la fase, así que dos órdenes superpuestas (IP + dominio)
cuentan dos veces. Medimos también con la unión de intervalos (`pruebas/puntaje_union.py`) y
elegimos la estrategia por ese número. No enviamos órdenes duplicadas para aprovechar esto.

## Supuestos

- La marca de agua extraída identifica la señal; el prefijo indica oficial o licenciatario.
- Dominio base = últimas dos etiquetas del host (`s1.pelotaya.test` → `pelotaya.test`).
- IP sin datos de DNS pasivo = compartida (se bloquea solo por dominio).
- Los servidores hermanos detectados por DNS pasivo son del mismo operador si comparten dominio base y
  su IP no aloja otros sitios. El juez puede rechazar cada uno.
- La firma HMAC de demostración reemplaza a la firma digital real.

## Qué existía antes del evento

- El simulador, los datos y el verificador son del repo oficial del desafío.
- Solo biblioteca estándar de Python. No usamos código propio previo.
- Desarrollado durante el hackathon con asistencia de IA (Claude).

## Estructura

```
plataforma/motor.py               circuito completo y estrategias
plataforma/web.py                 panel del juez, transparencia, vista de expediente
plataforma/verificar_evidencia.py verificación de integridad y exportación a entrega/
plataforma/usuarios_demo.json     usuarios de demostración (hash PBKDF2)
pruebas/                          comparador de estrategias, escenario de estrés, juez automático de prueba
entrega/                          expediente y auditoría del partido final, propuesta normativa
```
