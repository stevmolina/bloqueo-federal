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
import sys
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


def calcular_sello(exp: dict) -> str:
    """Seal of a case: SHA-256 over the evidence and analysis the judge saw when the case was created."""
    contenido = {"id": exp["id"], "tipo": exp["tipo_sellado"], "host_stream": exp["host_stream"],
                 "ip_servidor": exp["ip_servidor"], "clasificacion": exp["clasificacion"],
                 "riesgo_colateral": exp["riesgo_colateral"], "plan": exp["plan"],
                 "evidencia": exp["evidencia"][:exp["n_evidencia_sellada"]]}
    return sha256_hex(json.dumps(contenido, sort_keys=True, ensure_ascii=False).encode("utf-8"))


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
        self.jueces_info = [{"id": j["id"], "nombre": j.get("nombre", j["id"])} for jz in juzgados["juzgados"] for j in jz["jueces"]]
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

    # ---- arranque
    def iniciar(self) -> None:
        _, self.partido = self.api.pedir("/partido")
        self.fin_min = float(self.partido.get("fin_min", 105))
        _, self.proveedores = self.api.pedir("/proveedores")
        self.audit.registrar("plataforma_iniciada", None, estrategia=self.args.estrategia,
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
            crudo = base64.b64decode(contenido) if contenido else b""
        except ValueError:
            crudo = contenido.encode("utf-8")
        h_captura = sha256_hex(crudo) if crudo else None
        if crudo:
            # The capture itself is kept, so anyone can recompute its hash later.
            dir_cap = self.salida / "capturas"
            dir_cap.mkdir(parents=True, exist_ok=True)
            archivo = dir_cap / f"{h_captura}.{captura.get('formato') or 'bin'}"
            if not archivo.exists():
                archivo.write_bytes(crudo)
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
        if self.args.prediccion_temprana and exp["estado"] == "pendiente_juez":
            # Linked infrastructure is proposed now, so the judge reviews it together with the live case (one batch).
            self.seguro(self.predecir, exp)

    def crear_expediente(self, host: str, ip: str, asn: Any, motivo: str, evidencia: List[dict], tipo: str,
                         marca: Optional[str] = None, origen: Optional[str] = None) -> dict:
        riesgo = self.evaluar_riesgo(host, ip)
        plan = self.planificar(host, ip, riesgo)
        exp = {"id": self.nuevo_id("EXP-2026"), "tipo": tipo, "creado_min": self.minuto, "estado": "pendiente_juez",
               "sitio": dominio_base(host), "host_stream": host, "ip_servidor": ip, "asn": asn, "marca": marca,
               "origen": origen, "clasificacion": motivo, "riesgo_colateral": riesgo, "plan": plan,
               "vence_min": int(self.fin_min), "evidencia": evidencia, "decision": None, "ordenes": [],
               "ratificado_por": [], "tipo_sellado": tipo, "n_evidencia_sellada": len(evidencia)}
        exp["sello"] = calcular_sello(exp)
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
        if exp.get("predicho"):
            return
        exp["predicho"] = True
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
                    # Dominios hermanos: en una IP dedicada, los otros dominios del MISMO sitio en esa IP también se
                    # bloquean por dominio (colateral 0; única cobertura en proveedores que solo aceptan dominio).
                    if self.args.hermanos and not riesgo["ip_compartida"]:
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
            if nuevo == "fallida":
                self.fallas_por_proveedor[pid] = self.fallas_por_proveedor.get(pid, 0) + 1
                if not self.args.sin_reintento:
                    self.reintentar(o)

    def reintentar(self, o: dict) -> None:
        exp = self.expedientes[o["expediente_id"]]
        juez = self.juez_firmante(exp["decision"]["juez_id"])
        if juez is None:
            # El juez que aprobó ya no está de turno: el reintento lo firma el juez entrante.
            exp.setdefault("reintentos_pendientes", []).append(o)
            self.audit.registrar("reintento_pendiente_juez", self.minuto, orden_id=o["orden_id"])
            return
        self.enviar_orden(exp, {"proveedor": o["proveedor"], "tipo": o["tipo"], "objetivo": o["objetivo"]}, juez,
                          reintento_de=o["orden_id"])

    # ---- reclamos
    def procesar_reclamo(self, rc: dict) -> None:
        self.audit.registrar("reclamo_recibido", self.minuto, reclamo=rc)
        o = next((x for (pid, oid), x in self.ordenes.items()
                  if pid == rc["proveedor"] and x["estado"] in ("recibida", "aplicada")
                  and ((x["tipo"] == "ip" and rc["dominio"] in self.dns_ip(x["objetivo"]).get("dominios", []))
                       or (x["tipo"] == "dominio" and x["objetivo"] == rc["dominio"]))), None)
        if o is None:
            return
        juez = self.de_turno[0] if self.de_turno else None
        if juez is None:
            return
        firma = firmar(self.claves[juez][1], f"LEVANTAR|{o['orden_id']}|{juez}")
        codigo, r = self.api.pedir(f"/proveedores/{o['proveedor']}/ordenes/{o['orden_id']}/levantar",
                                   {"juez_id": juez, "firma": firma, "motivo": f"Reclamo {rc['id']}: {rc['dominio']}"})
        if codigo == 200:
            o["estado"] = "levantada"
        self.audit.registrar("orden_levantada_por_reclamo", self.minuto, orden_id=o["orden_id"], juez_id=juez,
                             codigo=codigo, reclamo=rc["id"])
        exp = self.expedientes[o["expediente_id"]]
        if o["tipo"] == "ip" and codigo == 200:
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
        return est["minuto_actual"] < self.fin_min + 5.5 or (self.args.web and not self.args.salir_al_final)

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

    # ---- cola del juez (orden de revisión y lotes)
    def alcance(self, exp: dict) -> int:
        """Provider customers reached by the case's plan (audience protected if approved)."""
        clientes = {p["id"]: p.get("clientes", 0) for p in self.proveedores}
        return sum(clientes.get(pid, 0) for pid in {i["proveedor"] for i in exp["plan"]})

    def grupos_pendientes(self, pendientes: List[dict]) -> List[List[dict]]:
        """Batch = same site or same watermark (same operation); union-find over pending cases."""
        if not self.args.lote:
            return [[x] for x in pendientes]
        padre = list(range(len(pendientes)))

        def raiz(i: int) -> int:
            while padre[i] != i:
                padre[i] = padre[padre[i]]
                i = padre[i]
            return i
        for i, a in enumerate(pendientes):
            for j in range(i):
                b = pendientes[j]
                if a["sitio"] == b["sitio"] or (a.get("marca") and a.get("marca") == b.get("marca")
                                               and a.get("tipo") != "preventivo" and b.get("tipo") != "preventivo"):
                    padre[raiz(i)] = raiz(j)
        grupos: Dict[int, List[dict]] = {}
        for i, x in enumerate(pendientes):
            grupos.setdefault(raiz(i), []).append(x)
        return list(grupos.values())

    def clave_cola(self, grupo: List[dict]) -> tuple:
        t = min(x["creado_min"] for x in grupo)
        if self.args.cola == "fifo":
            return (t,)
        preventivo = all(x.get("tipo") == "preventivo" for x in grupo)
        if self.args.cola == "confirmados":
            return (preventivo, t)
        # audiencia: confirmados primero, luego más clientes alcanzados, sitios repetidos, más evidencia
        sitios = {x["sitio"] for x in grupo}
        repite = any(y["sitio"] in sitios and y not in grupo for y in self.expedientes.values())
        alc = max(self.alcance(x) for x in grupo)
        ev = sum(len(x["evidencia"]) for x in grupo if x.get("tipo") != "preventivo")
        return (preventivo, -alc, not repite, -ev, t)

    def siguiente_revision(self) -> Optional[dict]:
        items = []
        if self.args.orden_marco and self.marcos_a_ratificar():
            t = getattr(self, "cambio_turno_min", -1e9)
            # Ratifying unblocks every new server of already-approved sites: top priority unless FIFO.
            items.append(((t,) if self.args.cola == "fifo" else (False, -1e18), {"tipo": "ratificacion", "exps": []}))
        pend = [x for x in self.expedientes.values() if x["estado"] == "pendiente_juez"]
        for g in self.grupos_pendientes(pend):
            items.append((self.clave_cola(g), {"tipo": "expedientes", "exps": [x["id"] for x in g]}))
        if not items:
            return None
        items.sort(key=lambda kv: kv[0])
        return items[0][1]

    def juez_serial(self) -> None:
        """TEST ONLY: one judge, one review at a time, S match-minutes per review (case, batch or ratification)."""
        S = self.args.juez_serial
        if not self.de_turno:
            self.revision = None
            return
        juez = self.de_turno[0]
        r = getattr(self, "revision", None)
        inicio = self.minuto
        if r is not None:
            if r["juez"] != juez:
                self.audit.registrar("revision_interrumpida_por_turno", self.minuto, items=r["exps"], tipo=r["tipo"])
                self.revision = None
            elif self.minuto >= r["fin"]:
                self.revision = None
                inicio = r["fin"]
                if r["tipo"] == "ratificacion":
                    self.ratificar(juez)
                else:
                    lote = len(r["exps"]) > 1
                    for eid in r["exps"]:
                        self.decidir(eid, juez, True, "aprobación simulada (juez serial, prueba)"
                                     + (f" · lote de {len(r['exps'])} expedientes" if lote else ""))
            else:
                return
        item = self.siguiente_revision()
        if item:
            item.update(juez=juez, inicio=inicio, fin=inicio + S)
            self.revision = item
            self.audit.registrar("revision_iniciada", self.minuto, tipo=item["tipo"], expedientes=item["exps"],
                                 fin_min=item["fin"])

    def auto_juez(self) -> None:
        """TEST ONLY: simulates the on-duty judge approving after a fixed delay (match minutes)."""
        if self.args.juez_serial is not None:
            return self.juez_serial()
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
        if self.args.web:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from web import Web
            Web(self, self.args.web).iniciar()
        n = 0
        while True:
            n += 1
            if n % 25 == 0:
                self.seguro(self.exportar)
            try:
                sigue = self.tick()
            except Exception as err:  # never let one bad response stop the match
                self.audit.registrar("error", self.minuto, error=repr(err))
                sigue = True
            if not sigue:
                break
            if self.minuto >= self.fin_min + 5.5 and not getattr(self, "_cerrado", False):
                self._cerrado = True
                self.seguro(self.exportar)
                self.audit.registrar("partido_cerrado", self.minuto, expedientes=len(self.expedientes))
            time.sleep(self.args.intervalo)
        self.exportar()
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
    ap.add_argument("--hermanos", action="store_true", default=True,
                    help="en IP dedicada, bloquear también por dominio los otros dominios del mismo sitio")
    ap.add_argument("--juez-serial", type=float, default=None,
                    help="SOLO PRUEBAS: un juez revisa un caso (o lote, o ratificación) a la vez, S minutos cada uno")
    ap.add_argument("--cola", choices=["fifo", "confirmados", "audiencia"], default="audiencia",
                    help="orden de la cola del juez")
    ap.add_argument("--lote", action="store_true", default=True, help="agrupar expedientes del mismo sitio/marca en una decisión")
    ap.add_argument("--prediccion-temprana", action="store_true", default=True,
                    help="buscar infraestructura vinculada al crear el expediente (no al aprobarlo), para revisarla en el mismo lote")
    ap.add_argument("--web", type=int, default=None, help="puerto del panel del juez (ej. 8090)")
    ap.add_argument("--salir-al-final", action="store_true", help="con --web, terminar al cerrar el partido")
    ap.add_argument("--intervalo", type=float, default=0.2, help="segundos reales entre consultas")
    args = ap.parse_args()
    Plataforma(args).correr()


if __name__ == "__main__":
    main()
