## Qué es

Bloqueo Federal es el MVP de una plataforma federal de órdenes de bloqueo en vivo. Mientras se juega el partido, convierte cada stream pirata detectado en un expediente con evidencia sellada, lo lleva al **juez de turno** para que firme, envía la orden a **todos** los proveedores de internet en el tipo de bloqueo que cada uno acepta, sigue la confirmación, reintenta si falla y levanta solos los bloqueos por IP al terminar. Cada paso queda en un registro de auditoría encadenado e inalterable.

## Cómo funciona

1. **Expediente verificable:** marca de agua contra la señal oficial, servidor (host, IP, ASN), DNS pasivo, captura con SHA-256 y sello del expediente. Descarta streams que no son del partido y nunca bloquea al licenciatario en sus dominios.
2. **Control de daño colateral:** si la IP es compartida (CDN, hosting compartido), solo bloqueo por dominio. Si es dedicada, IP + dominio como respaldo.
3. **Panel del juez:** login, cola con lo que está en vivo primero, un lote por sitio con cada servidor visible, firma en un clic, aviso sonoro y notificación. Solo firma el juez de turno; al cambio de turno el entrante ratifica las órdenes marco en un clic.
4. **Orden marco + infraestructura vinculada:** un servidor nuevo del mismo sitio o de la misma marca de agua filtrada se incorpora a la orden ya firmada. Los servidores hermanos encontrados en DNS pasivo se proponen como bloqueo preventivo, así quedan bloqueados antes de empezar a transmitir.
5. **Transparencia y reclamos:** registro público de qué se bloqueó, cuándo, por orden de quién y hasta cuándo; los reclamos levantan la orden con firma judicial y la reemplazan por un bloqueo más preciso.

## Resultados (verificador oficial, partido de práctica)

- 7 de 7 fases piratas bloqueadas; visibilidad residual 0,9 % con un juez que tarda 1 minuto por lote (el cliente de ejemplo: 86,5 %).
- 0 sitios legítimos afectados, 0 falsos positivos, 0 bloqueos por IP después del partido, 0 firmas fuera de turno.
- En un escenario de estrés con otros sitios, IPs y trampas: 8 de 8, 0,8 %, cero errores.
- Probamos 10+ estrategias y elegimos la mejor midiendo también con unión de intervalos, para no depender de que la métrica oficial cuenta dos veces órdenes superpuestas.

## Entregables

Repositorio con README, expediente y auditoría exportados del partido final y propuesta normativa de 1 página en `entrega/`. Python 3, solo biblioteca estándar.
