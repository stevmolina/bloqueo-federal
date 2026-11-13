# Propuesta normativa: bloqueo judicial en vivo de transmisiones ilegales

**Qué resuelve.** Hoy el bloqueo en vivo depende de una sola fiscalía y un solo juzgado, sin un procedimiento formal ni un canal estándar hacia todos los proveedores. La orden llega por las cámaras empresarias, los proveedores chicos no pueden reaccionar en tiempo real y bloquear una IP compartida puede tirar abajo servicios legítimos. Proponemos que una ley o resolución establezca lo siguiente.

**1. Orden marco por evento, firmada por un juez.** Antes de cada evento, el titular de derechos pide una orden marco para ese partido y su señal (marcas de agua). Durante el partido, cada sitio nuevo requiere la aprobación del **juez de turno** en una plataforma; un nuevo servidor del *mismo* sitio o de la *misma* marca de agua filtrada se incorpora a la orden ya firmada por ese juez. Ningún bloqueo sin firma judicial. *Por qué:* da velocidad sin quitarle al juez la decisión; Italia bloquea sin juez y tuvo bloqueos de sitios legítimos.

**2. Turnos judiciales y firma digital.** Cada juez firma solo durante su turno, con su usuario y firma digital. Al cambio de turno, lo pendiente pasa al juez entrante, que ratifica las órdenes marco vigentes en un solo acto. *Por qué:* un partido cruza turnos; la orden no puede quedar sin responsable.

**3. Registro nacional de proveedores, obligatorio y actualizado.** Todo proveedor de acceso a internet registrado ante el regulador declara un punto de contacto técnico (API) y qué tipos de bloqueo aplica (IP, dominio). *Por qué:* hoy no hay un registro actualizado de todos los proveedores; sin él la orden no llega a todos.

**4. Plazos máximos y confirmación.** El proveedor confirma la aplicación por la misma vía en un plazo máximo (propuesta: 5 minutos para grandes, 15 para chicos, ajustable por reglamento). Si falla, la plataforma reintenta y queda registrado. Los bloqueos por IP vencen solos al terminar el evento; por dominio, según lo que fije la orden. *Por qué:* sin plazo ni confirmación no hay forma de saber si la orden se cumplió.

**5. Control de daño colateral.** Antes de pedir el bloqueo, la plataforma debe mostrar al juez qué otros sitios comparten la IP (DNS pasivo). Si la IP es compartida (CDN, hosting compartido), **solo se permite bloqueo por dominio**. El licenciatario autorizado, en sus dominios, nunca se bloquea. *Por qué:* es la principal objeción de los proveedores y la causa de los errores en otros países.

**6. Evidencia verificable.** Cada expediente incluye la marca de agua que prueba que es la señal del evento, el servidor (host, IP, proveedor de hosting), la captura con su huella SHA-256 y sellos de tiempo, y un registro de auditoría encadenado e inalterable. *Por qué:* cualquier alteración posterior debe poder detectarse; protege al juez, al proveedor y al afectado.

**7. Reclamos con respuesta rápida.** Un sitio afectado por error reclama en la plataforma; el juez de turno puede levantar la orden con firma y reemplazarla por un bloqueo más preciso. Plazo de respuesta durante el evento (propuesta: 15 minutos). *Por qué:* un error durante un partido no puede esperar días.

**8. Transparencia pública.** Registro público de qué se bloqueó, cuándo, por orden de qué juez y hasta cuándo, con la evidencia disponible para los afectados. *Por qué:* da control social y previene abusos.

**9. Costos y responsabilidades.** El reglamento fija quién paga la operación de la plataforma y la adecuación de los proveedores chicos, y exime de responsabilidad al proveedor que cumple una orden firmada en plazo. *Por qué:* los proveedores chicos no pueden asumir solos el costo de reaccionar en tiempo real.

*Este documento no es asesoramiento legal. Los plazos son propuestas para discutir. Contexto según el material del desafío: bloqueos en vivo desde 2025 (UFEIC y Juzgado de Garantías N.º 4 de San Isidro), 182 dominios pedidos para el Superclásico del 1 de noviembre de 2026 y objeciones de CABASE.*
