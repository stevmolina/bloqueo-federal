# Entrega

| Archivo | Qué es |
|---|---|
| `propuesta_normativa.md` | Propuesta normativa de 1 página |
| `expediente_*.json` | Expediente de ejemplo exportado (evidencia, sello, plan por proveedor, decisión firmada) |
| `auditoria.jsonl` | Registro de auditoría encadenado con hashes |
| `expedientes_todos.json` | Todos los expedientes y detecciones descartadas de la corrida |
| `registro_simulador.jsonl` | Registro del simulador de esa corrida |
| `verificacion.json` | Resultado de `plataforma/verificar_evidencia.py` (cadena, sellos, capturas, firmas) |
| `puntaje_verificar.txt` | Salida de `evaluacion/verificar.py` |

**Estado:** PROVISORIO. Estos archivos salen de un partido de PRÁCTICA (`escenario_practica.json`, x10) con el juez firmando
por el panel web. Se reemplazan por los del partido final apenas se corra.

Para verificar: `python3 plataforma/verificar_evidencia.py <carpeta de la corrida> --juzgados ../desafio-futbol/datos/juzgados.json`
