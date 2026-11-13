#!/usr/bin/env python3
"""Plataforma federal de órdenes de bloqueo en vivo — motor (stdlib only, Python 3.9+).

Circuito: detección → expediente con evidencia → juez de turno → órdenes a cada proveedor
→ confirmación / reintento → vencimiento → auditoría encadenada.

Las estrategias (cómo elegir IP o dominio, reintentos, redundancia) se eligen por línea de
comandos para poder compararlas con evaluacion/verificar.py.
"""
import argparse
import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ----------------------------------------------------------------------------- utilidades


def sha256_hex(datos: bytes) -> str:
    return hashlib.sha256(datos).hexdigest()


def firmar(clave: str, mensaje: str) -> str:
    return hmac.new(clave.encode("utf-8"), mensaje.encode("utf-8"), hashlib.sha256).hexdigest()


def dominio_base(host: str) -> str:
    """Registrable domain approximation: last two labels (s1.pelotaya.test -> pelotaya.test)."""
    partes = host.lower().strip(".").split(".")
    return ".".join(partes[-2:]) if len(partes) >= 2 else host.lower()


def host_de_url(url: str) -> str:
    try:
        return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower()
    except IndexError:
        return ""


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/")

    def pedir(self, ruta: str, cuerpo: Optional[dict] = None) -> Tuple[int, Any]:
        datos = json.dumps(cuerpo).encode("utf-8") if cuerpo is not None else None
        req = urllib.request.Request(self.base + ruta, data=datos, headers={"Content-Type": "application/json"})
        for intento in range(3):
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, json.loads(resp.read())
            except urllib.error.HTTPError as err:
                try:
                    return err.code, json.loads(err.read())
                except ValueError:
                    return err.code, {"error": str(err)}
            except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                if intento == 2:
                    return 0, {"error": f"sin conexión: {err}"}
                time.sleep(0.3)
        return 0, {"error": "sin respuesta"}


# ----------------------------------------------------------------------------- auditoría


class Auditoria:
    """Append-only JSONL log; each entry carries the hash of the previous one (hash chain)."""

    def __init__(self, ruta: Path):
        self.ruta = ruta
        self.ruta.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.previo = "0" * 64
        self.n = 0
        self.f = open(ruta, "w", encoding="utf-8")

    def registrar(self, evento: str, minuto: Optional[float], **datos: Any) -> str:
        with self.lock:
            self.n += 1
            entrada = {"n": self.n, "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "min": minuto,
                       "evento": evento, "datos": datos, "hash_previo": self.previo}
            cuerpo = json.dumps(entrada, ensure_ascii=False, sort_keys=True)
            entrada["hash"] = sha256_hex(cuerpo.encode("utf-8"))
            self.previo = entrada["hash"]
            self.f.write(json.dumps(entrada, ensure_ascii=False, sort_keys=True) + "\n")
            self.f.flush()
            return entrada["hash"]


def verificar_auditoria(ruta: Path) -> Tuple[bool, str]:
    previo = "0" * 64
    i = 0
    with open(ruta, encoding="utf-8") as f:
        for i, linea in enumerate(f, start=1):
            e = json.loads(linea)
            h = e.pop("hash")
            if e["hash_previo"] != previo:
                return False, f"cadena rota en la entrada {i}: hash_previo no coincide"
            if sha256_hex(json.dumps(e, ensure_ascii=False, sort_keys=True).encode("utf-8")) != h:
                return False, f"entrada {i} alterada: su hash no coincide"
            previo = h
    return True, f"auditoría íntegra ({i} entradas)"


# ----------------------------------------------------------------------------- motor


class Plataforma:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.api = Api(args.servidor)
        self.salida = Path(args.salida)
        self.audit = Auditoria(self.salida / "auditoria.jsonl")
        juzgados = json.loads(Path(args.juzgados).read_text(encoding="utf-8"))
        # Claves de firma de demostración: solo se usan después de que el juez aprobó.
        self.claves = {j["id"]: (jz["id"], j["clave_firma_demo"]) for jz in juzgados["juzgados"] for j in jz["jueces"]}
        self.partido: dict = {}
        self.fin_min = 105.0
        self.proveedores: List[dict] = []
        self.expedientes: Dict[str, dict] = {}       # id -> expediente
        self.por_objetivo: Dict[str, str] = {}       # clave de stream -> expediente id
        self.descartes: List[dict] = []
        self.ordenes: Dict[Tuple[str, str], dict] = {}  # (proveedor, orden_id) -> orden
        self.fallas_por_proveedor: Dict[str, int] = {}
        self.dns_cache: Dict[str, dict] = {}
        self.desde_det = -1.0
        self.desde_rec = -1.0
        self.minuto = 0.0
        self.de_turno: List[str] = []
        self.seq = 0
        self.lock = threading.RLock()
        # Costo/adaptativo: estadística por proveedor aprendida en vivo (consultando el estado de las órdenes).
        self.clientes: Dict[str, int] = {}
        self.stats: Dict[str, dict] = {}
        self.metricas = {"ticks": 0, "tick_max_s": 0.0, "tick_total_s": 0.0, "latencias_det_orden": [],
                         "copias_extra": 0, "reintentos": 0, "reintentos_evitados": 0}

    # ---- arranque
    def iniciar(self) -> None:
        _, self.partido = self.api.pedir("/partido")
        self.fin_min = float(self.partido.get("fin_min", 105))
        _, self.proveedores = self.api.pedir("/proveedores")
        self.clientes = {p["id"]: int(p.get("clientes", 0)) for p in self.proveedores}
        self.stats = {p["id"]: {"n": 0, "fallas": 0, "demoras": []} for p in self.proveedores}
        self.audit.registrar("plataforma_iniciada", None, estrategia=self.args.estrategia, modo=self.args.modo,
                             partido=self.partido.get("id"), proveedores=[p["id"] for p in self.proveedores])

    def nuevo_id(self, prefijo: str) -> str:
        self.seq += 1
        return f"{prefijo}-{self.seq:04d}"

    # ---- clasificación de la detección
    def clasificar(self, d: dict) -> Tuple[str, str]:
        marca = d.get("marca_de_agua_extraida") or ""
        validas = self.partido.get("marcas_de_agua_validas", [])
        licenciatarios = self.partido.get("licenciatarios", [])
        host = (d.get("host_stream") or "").lower()
        pagina = host_de_url(d.get("pagina", ""))
        if not marca:
            return "descartada", "sin marca de agua: no se puede probar que sea la señal del partido"
        coincide = next((v for v in validas if marca.startswith(v["prefijo"] + "-") or marca == v["prefijo"]), None)
        if coincide is None:
            return "descartada", f"la marca {marca} no corresponde a este partido"
        for lic in licenciatarios:
            if marca.startswith(lic["prefijo_marca"]):
                autorizados = {x.lower() for x in lic.get("dominios_autorizados", [])}
                if host in autorizados or (pagina in autorizados and dominio_base(host) in {dominio_base(a) for a in autorizados}):
                    return "legitima", f"licenciatario autorizado ({lic['nombre']}) en su propio dominio"
                return "pirata", f"señal del licenciatario {lic['nombre']} retransmitida en un dominio no autorizado"
        return "pirata", f"marca de agua de la señal oficial ({coincide['origen']}) en un dominio no autorizado"

    # ---- riesgo colateral
    def dns_ip(self, ip: str) -> dict:
        if ip not in self.dns_cache:
            codigo, r = self.api.pedir(f"/dns-pasivo?ip={ip}")
            self.dns_cache[ip] = r if codigo == 200 else {"ip": ip, "dominios": [], "error": r.get("error")}
        return self.dns_cache[ip]

    def evaluar_riesgo(self, host: str, ip: str) -> dict:
        info = self.dns_ip(ip)
        dominios = info.get("dominios", [])
        base = dominio_base(host)
        ajenos = sorted(x for x in dominios if dominio_base(x) != base)
        org = (info.get("organizacion") or "")
        pista_compartida = any(p in org.lower() for p in ("cdn", "compartid", "shared"))
        compartida = bool(ajenos) or pista_compartida or not dominios
        return {"ip": ip, "asn": info.get("asn"), "organizacion": org, "dominios_en_ip": dominios,
                "dominios_ajenos": ajenos, "ip_compartida": compartida,
                "motivo": ("la IP aloja otros sitios: " + ", ".join(ajenos[:5]) + ("…" if len(ajenos) > 5 else ""))
                if ajenos else ("organización de hosting compartido/CDN" if pista_compartida
                                else ("sin datos de DNS pasivo: se asume compartida" if not dominios
                                      else "IP dedicada al sitio pirata"))}

    # ---- expediente
    def procesar_deteccion(self, d: dict) -> None:
        clase, motivo = self.clasificar(d)
        host, ip = d["host_stream"].lower(), d["ip_servidor"]
        if clase != "pirata":
            self.descartes.append({"deteccion": d["id"], "clase": clase, "motivo": motivo, "host": host, "ip": ip})
            self.audit.registrar("deteccion_descartada", self.minuto, deteccion=d["id"], clase=clase, motivo=motivo,
                                 host=host, ip=ip)
            return
        clave = f"{host}|{ip}"
        captura = d.get("captura", {})
        contenido = captura.get("contenido_b64", "")
        try:
            h_captura = sha256_hex(base64.b64decode(contenido)) if contenido else None
        except ValueError:
            h_captura = sha256_hex(contenido.encode("utf-8"))
        evidencia = {"deteccion": d["id"], "minuto": d["minuto"], "pagina": d.get("pagina"),
                     "stream_url": d.get("stream_url"), "marca_de_agua": d.get("marca_de_agua_extraida"),
                     "sha256_captura": h_captura, "captura_min": captura.get("capturada_min"),
                     "formato": captura.get("formato"), "duracion_seg": captura.get("duracion_seg"),
                     "promocion": d.get("promocion", []),
                     "sha256_deteccion": sha256_hex(json.dumps(d, sort_keys=True).encode("utf-8"))}
        if clave in self.por_objetivo:
            exp = self.expedientes[self.por_objetivo[clave]]
            exp["evidencia"].append(evidencia)
            if exp.get("tipo") == "preventivo":
                exp["tipo"] = "confirmado"  # el stream apareció donde lo predijimos
            self.audit.registrar("evidencia_agregada", self.minuto, expediente=exp["id"], deteccion=d["id"],
                                 sha256_captura=h_captura)
            return
        exp = self.crear_expediente(host, ip, d.get("asn"), motivo, [evidencia], "deteccion",
                                    marca=evidencia["marca_de_agua"])
        if self.args.orden_marco:
            # Orden marco: el juez de turno ya aprobó este sitio o esta misma marca de agua (misma fuente
            # filtrada). El nuevo servidor se agrega bajo esa orden, firmado por ese juez de turno.
            marco, juez = self.buscar_marco(exp)
            if marco:
                exp["orden_marco"] = marco["id"]
                self.decidir(exp["id"], juez, True,
                             f"ampliación de la orden marco {marco['id']} (mismo sitio o misma marca de agua)")

    def crear_expediente(self, host: str, ip: str, asn: Any, motivo: str, evidencia: List[dict], tipo: str,
                         marca: Optional[str] = None, origen: Optional[str] = None) -> dict:
        riesgo = self.evaluar_riesgo(host, ip)
        plan = self.planificar(host, ip, riesgo)
        exp = {"id": self.nuevo_id("EXP-2026"), "tipo": tipo, "creado_min": self.minuto, "estado": "pendiente_juez",
               "sitio": dominio_base(host), "host_stream": host, "ip_servidor": ip, "asn": asn, "marca": marca,
               "origen": origen, "clasificacion": motivo, "riesgo_colateral": riesgo, "plan": plan,
               "vence_min": int(self.fin_min), "evidencia": evidencia, "decision": None, "ordenes": [],
               "ratificado_por": []}
        exp["sello"] = sha256_hex(json.dumps({k: exp[k] for k in ("id", "tipo", "host_stream", "ip_servidor",
                                                                    "clasificacion", "riesgo_colateral", "plan",
                                                                    "evidencia")},
                                             sort_keys=True).encode("utf-8"))
        self.expedientes[exp["id"]] = exp
        self.por_objetivo[f"{host}|{ip}"] = exp["id"]
        self.audit.registrar("expediente_creado", self.minuto, expediente=exp["id"], tipo=tipo, host=host, ip=ip,
                             plan=plan, sello=exp["sello"], ip_compartida=riesgo["ip_compartida"])
        self.notificar_juez(exp)
        return exp

    def buscar_marco(self, exp: dict) -> Tuple[Optional[dict], Optional[str]]:
        for x in self.expedientes.values():
            if x["estado"] != "aprobado" or x is exp or x.get("tipo") == "preventivo":
                continue
            mismo = x["sitio"] == exp["sitio"] or (exp.get("marca") and x.get("marca") == exp["marca"])
            if not mismo:
                continue
            for juez in [x["decision"]["juez_id"]] + x.get("ratificado_por", []):
                if juez in self.de_turno:
                    return x, juez
        return None, None

    # ---- predicción de infraestructura vinculada (DNS pasivo)
    def candidatos(self, host: str) -> List[str]:
        import re
        etiquetas = host.split(".")
        primera, resto = etiquetas[0], ".".join(etiquetas[1:])
        cands = set()
        m = list(re.finditer(r"\d+", primera))
        if m:
            u = m[-1]
            n = int(u.group())
            for k in (n - 1, n + 1, n + 2, n + 3):
                if k >= 0:
                    cands.add(primera[:u.start()] + str(k) + primera[u.end():] + "." + resto)
        for w in ("respaldo", "espejo", "mirror", "backup", "live", "tv", "www", "stream", "cdn", "vivo", "hd"):
            cands.add(f"{w}.{resto}")
            cands.add(f"{primera}-{w}.{resto}")
        if resto.count(".") >= 1:
            cands.add(resto)
        cands.discard(host)
        return sorted(cands)

    def predecir(self, exp: dict) -> None:
        for cand in self.candidatos(exp["host_stream"]):
            codigo, r = self.api.pedir(f"/dns-pasivo?dominio={cand}")
            if codigo != 200:
                continue
            for item in r.get("ips", []):
                ip = item["ip"]
                if f"{cand}|{ip}" in self.por_objetivo:
                    continue
                if any(x["ip_servidor"] == ip and not x["riesgo_colateral"]["ip_compartida"]
                       for x in self.expedientes.values()):
                    continue  # esa IP dedicada ya tiene expediente: el bloqueo por IP ya cubre este dominio
                motivo = (f"infraestructura vinculada a {exp['sitio']} (expediente {exp['id']}): el dominio {cand} "
                          f"del mismo sitio figura en DNS pasivo en {ip}. Bloqueo preventivo, sin stream detectado aún.")
                ev = [{"tipo": "dns_pasivo", "dominio": cand, "ip": ip, "consulta_min": self.minuto,
                       "sha256_respuesta": sha256_hex(json.dumps(r, sort_keys=True).encode("utf-8"))}]
                self.crear_expediente(cand, ip, item.get("asn"), motivo, ev, "preventivo", marca=exp.get("marca"),
                                      origen=exp["id"])

    def planificar(self, host: str, ip: str, riesgo: dict) -> List[dict]:
        """Per provider: list of (tipo, objetivo) orders according to the strategy."""
        e = self.args.estrategia
        plan = []
        for p in self.proveedores:
            caps = p.get("capacidades", [])
            objetivos: List[Tuple[str, str]] = []
            if e == "ip":
                if "ip" in caps:
                    objetivos.append(("ip", ip))
            elif e == "dominio":
                if "dominio" in caps:
                    objetivos.append(("dominio", host))
            else:  # inteligente / redundante
                if not riesgo["ip_compartida"] and "ip" in caps:
                    objetivos.append(("ip", ip))
                if "dominio" in caps and (riesgo["ip_compartida"] or self.args.ip_y_dominio or "ip" not in caps):
                    objetivos.append(("dominio", host))
                    # Costo: en una IP dedicada, los otros dominios del MISMO sitio en esa IP (DNS pasivo) también
                    # se bloquean por dominio. Colateral esperado = 0 (mismo dominio base) y es la única cobertura
                    # posible en proveedores que solo aceptan dominio (el bloqueo por IP no los alcanza).
                    if self.args.modo != "base" and not riesgo["ip_compartida"]:
                        base = dominio_base(host)
                        for otro in sorted(riesgo.get("dominios_en_ip", [])):
                            otro = otro.lower()
                            if otro != host and dominio_base(otro) == base:
                                objetivos.append(("dominio", otro))
            for tipo, obj in objetivos:
                plan.append({"proveedor": p["id"], "tipo": tipo, "objetivo": obj})
        return plan

    # ---- juez
    def notificar_juez(self, exp: dict) -> None:
        exp["notificado_min"] = self.minuto
        self.audit.registrar("juez_notificado", self.minuto, expediente=exp["id"], jueces_de_turno=self.de_turno)

    def decidir(self, exp_id: str, juez_id: str, aprueba: bool, motivo: str = "") -> Tuple[bool, str]:
        """Called by the judge UI (or the test auto-judge) after the judge logged in."""
        with self.lock:
            exp = self.expedientes.get(exp_id)
            if exp is None:
                return False, "expediente inexistente"
            if exp["estado"] != "pendiente_juez":
                return False, f"el expediente ya está {exp['estado']}"
            if juez_id not in self.de_turno:
                self.audit.registrar("firma_rechazada", self.minuto, expediente=exp_id, juez_id=juez_id,
                                     motivo="juez fuera de turno")
                return False, "el juez no está de turno"
            exp["decision"] = {"juez_id": juez_id, "juzgado_id": self.claves[juez_id][0], "aprueba": aprueba,
                               "minuto": self.minuto, "motivo": motivo,
                               "firma_decision": firmar(self.claves[juez_id][1],
                                                        f"DECISION|{exp_id}|{exp['sello']}|{'APRUEBA' if aprueba else 'RECHAZA'}")}
            exp["estado"] = "aprobado" if aprueba else "rechazado"
            self.audit.registrar("decision_juez", self.minuto, expediente=exp_id, juez_id=juez_id,
                                 aprueba=aprueba, firma=exp["decision"]["firma_decision"])
            if aprueba:
                for item in exp["plan"]:
                    copias = 1
                    if self.args.estrategia == "redundante" and self.fallas_por_proveedor.get(item["proveedor"], 0) > 0:
                        copias = 2
                    if self.args.modo in ("fallas", "costo"):
                        copias = self.copias(item["proveedor"])
                    for _ in range(copias):
                        self.enviar_orden(exp, item, juez_id)
                if self.args.prediccion and exp.get("tipo") != "preventivo":
                    self.seguro(self.predecir, exp)
            return True, "ok"

    def marcos_a_ratificar(self) -> List[dict]:
        return [x for x in self.expedientes.values()
                if x["estado"] == "aprobado" and x.get("tipo") != "preventivo"
                and not ({x["decision"]["juez_id"], *x.get("ratificado_por", [])} & set(self.de_turno))]

    def ratificar(self, juez_id: str) -> int:
        """Incoming judge ratifies, in one action, the framework orders of the previous shift."""
        with self.lock:
            if juez_id not in self.de_turno:
                return 0
            lista = self.marcos_a_ratificar()
            firma = firmar(self.claves[juez_id][1], "RATIFICA|" + "|".join(x["id"] + ":" + x["sello"] for x in lista))
            for x in lista:
                x.setdefault("ratificado_por", []).append(juez_id)
            self.audit.registrar("ordenes_marco_ratificadas", self.minuto, juez_id=juez_id,
                                 expedientes=[x["id"] for x in lista], firma=firma)
            return len(lista)

    def juez_firmante(self, preferido: str) -> Optional[str]:
        if preferido in self.de_turno:
            return preferido
        return None

    # ---- costo esperado por proveedor (aprendido en vivo)
    def tasa_falla(self, pid: str) -> float:
        s = self.stats.get(pid, {"n": 0, "fallas": 0})
        return (s["fallas"] + 0.5) / (s["n"] + 2.0)  # prior Beta(0.5, 1.5): ~25 % hasta tener datos

    def demora(self, pid: str) -> Tuple[float, float]:
        """(media, dispersión) de la demora observada recibida→aplicada, en minutos de partido."""
        d = self.stats.get(pid, {}).get("demoras", [])
        if len(d) < 2:
            return self.args.demora_prior, self.args.demora_prior * 0.5
        return sum(d) / len(d), max(d) - min(d)

    def copias(self, pid: str) -> int:
        """Copias paralelas de una orden (orden_id distinto, misma firma del juez) mientras el beneficio esperado
        en espectadores-minuto supere el costo operativo de una orden extra al proveedor.
        Beneficio de la copia k+1: cubrir el caso de que fallen las k anteriores (evita un reenvío que cuesta otra
        demora completa) y, en modo 'costo', aplicar antes (el mínimo de k+1 demoras independientes)."""
        n_clientes = self.clientes.get(pid, 0)
        f = self.tasa_falla(pid)
        media, disp = self.demora(pid)
        k = 1
        while k < self.args.max_copias:
            # todas las k fallan → sin la copia extra hay que esperar el fallo y reenviar (≈ otra demora media)
            ganancia = (f ** k) * media
            if self.args.modo == "costo":
                ganancia += disp * (1.0 / (k + 1) - 1.0 / (k + 2))
            if n_clientes * ganancia < self.args.costo_copia:
                break
            k += 1
        self.metricas["copias_extra"] += k - 1
        return k

    def activas_hermanas(self, o: dict) -> List[dict]:
        return [x for x in self.ordenes.values()
                if x is not o and x["expediente_id"] == o["expediente_id"] and x["proveedor"] == o["proveedor"]
                and x["tipo"] == o["tipo"] and x["objetivo"] == o["objetivo"] and x["estado"] in ("recibida", "aplicada")]

    def levantada_hermana(self, o: dict) -> bool:
        return any(x["expediente_id"] == o["expediente_id"] and x["proveedor"] == o["proveedor"]
                   and x["tipo"] == o["tipo"] and x["objetivo"] == o["objetivo"] and x["estado"] == "levantada"
                   for x in self.ordenes.values())

    # ---- órdenes
    def enviar_orden(self, exp: dict, item: dict, juez_id: str, reintento_de: Optional[str] = None) -> None:
        vence = exp["vence_min"]
        if vence <= self.minuto:
            return
        orden_id = self.nuevo_id(f"ord-{item['proveedor']}")
        orden = {"orden_id": orden_id, "expediente_id": exp["id"], "tipo": item["tipo"], "objetivo": item["objetivo"],
                 "vence_min": vence, "juzgado_id": self.claves[juez_id][0], "juez_id": juez_id}
        orden["firma"] = firmar(self.claves[juez_id][1],
                                f"{orden_id}|{orden['tipo']}|{orden['objetivo']}|{orden['vence_min']}|{juez_id}")
        codigo, r = self.api.pedir(f"/proveedores/{item['proveedor']}/ordenes", orden)
        registro = dict(orden, proveedor=item["proveedor"], estado=r.get("estado", "rechazada") if codigo == 202 else "rechazada",
                        enviada_min=self.minuto, respuesta=r, reintento_de=reintento_de, intentos=0)
        self.ordenes[(item["proveedor"], orden_id)] = registro
        if not exp["ordenes"] and exp.get("tipo") != "preventivo" and exp["evidencia"]:
            self.metricas["latencias_det_orden"].append(round(self.minuto - float(exp["evidencia"][0]["minuto"]), 3))
        exp["ordenes"].append(orden_id)
        self.audit.registrar("orden_enviada", self.minuto, expediente=exp["id"], proveedor=item["proveedor"],
                             orden_id=orden_id, tipo=item["tipo"], objetivo=item["objetivo"], juez_id=juez_id,
                             codigo=codigo, respuesta=r, reintento_de=reintento_de)

    def seguir_ordenes(self) -> None:
        for (pid, oid), o in list(self.ordenes.items()):
            if o["estado"] not in ("recibida",):
                continue
            codigo, r = self.api.pedir(f"/proveedores/{pid}/ordenes/{oid}")
            if codigo != 200:
                continue
            nuevo = r.get("estado")
            if nuevo == o["estado"]:
                continue
            o["estado"] = nuevo
            self.audit.registrar(f"orden_{nuevo}", self.minuto, proveedor=pid, orden_id=oid, expediente=o["expediente_id"])
            s = self.stats.setdefault(pid, {"n": 0, "fallas": 0, "demoras": []})
            if nuevo in ("aplicada", "fallida"):
                s["n"] += 1
                if nuevo == "aplicada" and r.get("aplicada_min") is not None and r.get("recibida_min") is not None:
                    s["demoras"].append(float(r["aplicada_min"]) - float(r["recibida_min"]))
            if nuevo == "fallida":
                s["fallas"] += 1
                self.fallas_por_proveedor[pid] = self.fallas_por_proveedor.get(pid, 0) + 1
                if not self.args.sin_reintento:
                    if self.args.modo != "base" and (self.activas_hermanas(o) or self.levantada_hermana(o)):
                        # Otra copia de la misma orden sigue viva (o el bloqueo se levantó por reclamo): no reenviar.
                        # Si esa copia también falla, ella misma dispara el reenvío.
                        self.metricas["reintentos_evitados"] += 1
                    else:
                        self.metricas["reintentos"] += 1
                        self.reintentar(o)

    def reintentar(self, o: dict) -> None:
        exp = self.expedientes[o["expediente_id"]]
        juez = self.juez_firmante(exp["decision"]["juez_id"])
        if juez is None:
            # El juez que aprobó ya no está de turno: el reintento lo firma el juez entrante.
            exp.setdefault("reintentos_pendientes", []).append(o)
            self.audit.registrar("reintento_pendiente_juez", self.minuto, orden_id=o["orden_id"])
            return
        copias = self.copias(o["proveedor"]) if self.args.modo in ("fallas", "costo") else 1
        for _ in range(copias):
            self.enviar_orden(exp, {"proveedor": o["proveedor"], "tipo": o["tipo"], "objetivo": o["objetivo"]}, juez,
                              reintento_de=o["orden_id"])

    # ---- reclamos
    def procesar_reclamo(self, rc: dict) -> None:
        self.audit.registrar("reclamo_recibido", self.minuto, reclamo=rc)
        coinciden = [x for (pid, oid), x in self.ordenes.items()
                     if pid == rc["proveedor"] and x["estado"] in ("recibida", "aplicada")
                     and ((x["tipo"] == "ip" and rc["dominio"] in self.dns_ip(x["objetivo"]).get("dominios", []))
                          or (x["tipo"] == "dominio" and x["objetivo"] == rc["dominio"]))]
        if not coinciden:
            return
        if self.args.modo == "base":
            coinciden = coinciden[:1]
        juez = self.de_turno[0] if self.de_turno else None
        if juez is None:
            return
        reemplazados = set()
        for o in coinciden:  # con copias paralelas hay que levantar todas
            firma = firmar(self.claves[juez][1], f"LEVANTAR|{o['orden_id']}|{juez}")
            codigo, r = self.api.pedir(f"/proveedores/{o['proveedor']}/ordenes/{o['orden_id']}/levantar",
                                       {"juez_id": juez, "firma": firma, "motivo": f"Reclamo {rc['id']}: {rc['dominio']}"})
            if codigo == 200:
                o["estado"] = "levantada"
            self.audit.registrar("orden_levantada_por_reclamo", self.minuto, orden_id=o["orden_id"], juez_id=juez,
                                 codigo=codigo, reclamo=rc["id"])
            exp = self.expedientes[o["expediente_id"]]
            if o["tipo"] == "ip" and codigo == 200 and exp["id"] not in reemplazados:
                reemplazados.add(exp["id"])
                # Reemplazo por un bloqueo más preciso: el dominio del stream.
                self.enviar_orden(exp, {"proveedor": o["proveedor"], "tipo": "dominio", "objetivo": exp["host_stream"]},
                                  juez, reintento_de=o["orden_id"])

    # ---- ciclo
    def tick(self) -> bool:
        codigo, est = self.api.pedir("/estado")
        if codigo != 200:
            return True
        with self.lock:
            self.minuto = est["minuto_actual"]
            anteriores = self.de_turno
            self.de_turno = est.get("jueces_de_turno", [])
            if anteriores and anteriores != self.de_turno:
                self.audit.registrar("cambio_de_turno", self.minuto, salientes=anteriores, entrantes=self.de_turno)
                self.cambio_turno_min = self.minuto
                # Lo pendiente pasa al juez entrante: se le notifica de nuevo.
                for exp in self.expedientes.values():
                    if exp["estado"] == "pendiente_juez":
                        exp["notificado_min"] = self.minuto
                        self.audit.registrar("expediente_reasignado", self.minuto, expediente=exp["id"],
                                             a=self.de_turno)
            codigo, lote = self.api.pedir(f"/detecciones?desde={self.desde_det}")
            if codigo == 200:
                self.desde_det = lote.get("minuto_actual", self.desde_det)
                for d in lote.get("detecciones", []):
                    self.seguro(self.procesar_deteccion, d)
            self.seguro(self.auto_juez)
            self.seguro(self.seguir_ordenes)
            self.seguro(self.reintentos_turno)
            codigo, rl = self.api.pedir(f"/reclamos?desde={self.desde_rec}")
            if codigo == 200:
                self.desde_rec = rl.get("minuto_actual", self.desde_rec)
                for rc in rl.get("reclamos", []):
                    self.seguro(self.procesar_reclamo, rc)
        return est["minuto_actual"] < self.fin_min + 5.5

    def seguro(self, fn, *a) -> None:
        """Run one step; an error is logged and never blocks the rest of the circuit."""
        try:
            fn(*a)
        except Exception as err:
            self.audit.registrar("error", self.minuto, paso=fn.__name__, error=repr(err))

    def reintentos_turno(self) -> None:
        for exp in self.expedientes.values():
            pend = exp.get("reintentos_pendientes")
            if pend and self.de_turno:
                exp["reintentos_pendientes"] = []
                for o in pend:
                    self.enviar_orden(exp, {"proveedor": o["proveedor"], "tipo": o["tipo"], "objetivo": o["objetivo"]},
                                      self.de_turno[0], reintento_de=o["orden_id"])

    def auto_juez(self) -> None:
        """TEST ONLY: simulates the on-duty judge approving after a fixed delay (match minutes)."""
        if self.args.juez_auto is None:
            return
        if (self.args.orden_marco and self.de_turno and self.marcos_a_ratificar()
                and self.minuto - getattr(self, "cambio_turno_min", -1e9) >= self.args.juez_auto):
            self.ratificar(self.de_turno[0])
        for exp in list(self.expedientes.values()):
            if exp["estado"] == "pendiente_juez" and self.minuto - exp["notificado_min"] >= self.args.juez_auto and self.de_turno:
                self.decidir(exp["id"], self.de_turno[0], True, "aprobación simulada (prueba)")

    def exportar(self) -> None:
        (self.salida / "expedientes.json").write_text(
            json.dumps({"expedientes": list(self.expedientes.values()), "descartes": self.descartes},
                       ensure_ascii=False, indent=2), encoding="utf-8")

    def correr(self) -> None:
        self.iniciar()
        while True:
            t0 = time.monotonic()
            try:
                sigue = self.tick()
            except Exception as err:  # never let one bad response stop the match
                self.audit.registrar("error", self.minuto, error=repr(err))
                sigue = True
            dt = time.monotonic() - t0
            self.metricas["ticks"] += 1
            self.metricas["tick_total_s"] += dt
            self.metricas["tick_max_s"] = max(self.metricas["tick_max_s"], dt)
            if not sigue:
                break
            time.sleep(self.args.intervalo)
        self.exportar()
        m = dict(self.metricas)
        m["tick_medio_s"] = round(m["tick_total_s"] / max(1, m["ticks"]), 4)
        m["stats_proveedores"] = {pid: {"n": s["n"], "fallas": s["fallas"], "tasa_estimada": round(self.tasa_falla(pid), 3),
                                        "demora_media": round(self.demora(pid)[0], 2), "dispersion": round(self.demora(pid)[1], 2)}
                                  for pid, s in self.stats.items()}
        (self.salida / "metricas.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        self.audit.registrar("plataforma_finalizada", self.minuto, expedientes=len(self.expedientes),
                             ordenes=len(self.ordenes))


def main() -> None:
    ap = argparse.ArgumentParser(description="Plataforma federal de órdenes de bloqueo en vivo")
    ap.add_argument("--servidor", default="http://localhost:8080")
    ap.add_argument("--juzgados", default=str(Path(__file__).resolve().parent.parent / "datos" / "juzgados.json"))
    ap.add_argument("--salida", default="salida_plataforma")
    ap.add_argument("--estrategia", choices=["ip", "dominio", "inteligente", "redundante"], default="inteligente")
    ap.add_argument("--ip-y-dominio", action="store_true", default=True, help="en IP dedicada, enviar también bloqueo por dominio")
    ap.add_argument("--sin-reintento", action="store_true")
    ap.add_argument("--orden-marco", action="store_true", default=True,
                    help="un sitio ya aprobado por el juez de turno cubre sus nuevos servidores")
    ap.add_argument("--prediccion", action="store_true", default=True,
                    help="al aprobar, buscar en DNS pasivo servidores vinculados del sitio y proponer bloqueo preventivo")
    ap.add_argument("--juez-auto", type=float, default=None,
                    help="SOLO PRUEBAS: el juez de turno aprueba solo tras N minutos de partido")
    ap.add_argument("--intervalo", type=float, default=0.2, help="segundos reales entre consultas")
    ap.add_argument("--modo", choices=["base", "hermanos", "fallas", "costo"], default="costo",
                    help="base = motor actual; hermanos = + dominios hermanos en IP dedicada; fallas = + copias "
                         "por tasa de falla observada; costo = + copias también por demora (valor esperado)")
    ap.add_argument("--costo-copia", type=float, default=50000.0,
                    help="costo de una orden extra, en espectadores-minuto")
    ap.add_argument("--max-copias", type=int, default=3)
    ap.add_argument("--demora-prior", type=float, default=2.0, help="demora supuesta (min) hasta observar datos")
    args = ap.parse_args()
    Plataforma(args).correr()


if __name__ == "__main__":
    main()
