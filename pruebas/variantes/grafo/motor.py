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


def cuenta_promocion(url: str) -> str:
    """Normalize a promotion URL to the account/channel it belongs to
    (x.example/futbolya_ok/status/1001 -> x.example/futbolya_ok; discord.example/invite/abc -> same)."""
    try:
        resto = url.split("://", 1)[1]
    except IndexError:
        resto = url
    partes = [p for p in resto.lower().split("?", 1)[0].split("#", 1)[0].split("/") if p]
    if not partes:
        return ""
    salida = [partes[0]]
    for p in partes[1:]:
        if p in ("status", "statuses", "post", "posts", "p", "s", "m", "message", "messages"):
            break
        salida.append(p)
        if len(salida) >= 3:
            break
    return "/".join(salida)


class Grafo:
    """Entity resolution of pirate infrastructure: union-find over typed nodes
    (dom:, base:, ip:, marca:, promo:). Only evidence from detections classified as pirate and
    DNS records of dedicated IPs enter the graph; shared-hosting/CDN IPs are never nodes."""

    def __init__(self) -> None:
        self.padre: Dict[str, str] = {}
        self.aristas: List[Tuple[str, str, str]] = []

    def raiz(self, x: str) -> str:
        self.padre.setdefault(x, x)
        while self.padre[x] != x:
            self.padre[x] = self.padre[self.padre[x]]
            x = self.padre[x]
        return x

    def unir(self, a: str, b: str, motivo: str) -> None:
        ra, rb = self.raiz(a), self.raiz(b)
        self.aristas.append((a, b, motivo))
        if ra != rb:
            self.padre[ra] = rb

    def mismo(self, a: str, b: str) -> bool:
        if a not in self.padre or b not in self.padre:
            return False
        return self.raiz(a) == self.raiz(b)

    def componente(self, x: str) -> List[str]:
        if x not in self.padre:
            return [x]
        r = self.raiz(x)
        return sorted(n for n in self.padre if self.raiz(n) == r)


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
        self.grafo = Grafo()
        self.dns_dom_cache: Dict[str, Tuple[int, dict]] = {}
        self.expandidos: set = set()

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
            h_captura = sha256_hex(base64.b64decode(contenido)) if contenido else None
        except ValueError:
            h_captura = sha256_hex(contenido.encode("utf-8"))
        evidencia = {"deteccion": d["id"], "minuto": d["minuto"], "pagina": d.get("pagina"),
                     "stream_url": d.get("stream_url"), "marca_de_agua": d.get("marca_de_agua_extraida"),
                     "sha256_captura": h_captura, "captura_min": captura.get("capturada_min"),
                     "formato": captura.get("formato"), "duracion_seg": captura.get("duracion_seg"),
                     "promocion": d.get("promocion", []),
                     "sha256_deteccion": sha256_hex(json.dumps(d, sort_keys=True).encode("utf-8"))}
        self.vincular_deteccion(d, host, ip)
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
                             f"ampliación de la orden marco {marco['id']}: misma operación pirata según el grafo "
                             f"de infraestructura ({exp.get('vinculo_marco', '')})")

    # ---- grafo de infraestructura
    def ip_dedicada(self, host: str, ip: str) -> bool:
        return not self.evaluar_riesgo(host, ip)["ip_compartida"]

    def serial_marca(self, marca: str) -> Optional[str]:
        """Forensic watermark with a per-source serial (LP26-PRA-OFI-S048211). A bare licensee mark
        (LP26-PRA-LIC-NORTE) identifies a licensee, not a pirate source: never a graph node."""
        for v in self.partido.get("marcas_de_agua_validas", []):
            if marca.startswith(v["prefijo"] + "-") and len(marca) > len(v["prefijo"]) + 1:
                return marca
        return None

    def vincular_deteccion(self, d: dict, host: str, ip: str) -> None:
        g = self.grafo
        nodo = "dom:" + host
        g.unir(nodo, "base:" + dominio_base(host), "mismo dominio base")
        pag = host_de_url(d.get("pagina", ""))
        if pag:
            g.unir(nodo, "base:" + dominio_base(pag), f"página {pag} sirve el stream")
        if self.ip_dedicada(host, ip):
            g.unir(nodo, "ip:" + ip, "stream servido desde IP dedicada")
        serial = self.serial_marca(d.get("marca_de_agua_extraida") or "")
        if serial:
            g.unir(nodo, "marca:" + serial, "misma marca de agua forense")
        if not self.args.sin_promo:
            for p in d.get("promocion", []) or []:
                cuenta = cuenta_promocion(p.get("url", ""))
                if cuenta:
                    g.unir(nodo, "promo:" + cuenta, f"promocionado por {cuenta}")

    def vinculo(self, a: str, b: str) -> str:
        """Short human-readable explanation of why two hosts are in the same component."""
        comp = self.grafo.componente("dom:" + a)
        tipos = sorted({n.split(":", 1)[0] for n in comp})
        return f"componente de {len(comp)} nodos ({', '.join(tipos)}) que une {a} y {b}"

    def dns_dominio(self, dominio: str) -> Tuple[int, dict]:
        if dominio not in self.dns_dom_cache:
            self.dns_dom_cache[dominio] = self.api.pedir(f"/dns-pasivo?dominio={dominio}")
        return self.dns_dom_cache[dominio]

    def ip_con_expediente_dedicado(self, ip: str) -> bool:
        return any(x["ip_servidor"] == ip and not x["riesgo_colateral"]["ip_compartida"]
                   for x in self.expedientes.values())

    def expandir(self, exp: dict) -> None:
        """BFS over passive DNS from an approved case: dedicated IP -> its domains -> their IPs.
        Only dedicated IPs (all domains of the same base, not CDN/shared org) join the operation.
        A domain of the operation's own base seen on a shared IP gets a domain-only preventive case;
        nothing else on a shared IP is ever touched."""
        if not self.args.expansion:
            return
        raiz = exp["host_stream"]
        dominios = [raiz]
        ips = [exp["ip_servidor"]] if self.ip_dedicada(raiz, exp["ip_servidor"]) else []
        vistos_d, vistos_i = set(dominios), set(ips)
        consultas = 0
        while (dominios or ips) and consultas < 40:
            nuevos_d: List[str] = []
            for ip in ips:
                if ("ip", ip) in self.expandidos:
                    continue
                self.expandidos.add(("ip", ip))
                consultas += 1
                for dom in self.dns_ip(ip).get("dominios", []):
                    dom = dom.lower()
                    self.grafo.unir("dom:" + dom, "ip:" + ip, "DNS pasivo: dominio en IP dedicada")
                    self.grafo.unir("dom:" + dom, "base:" + dominio_base(dom), "mismo dominio base")
                    if dom not in vistos_d:
                        vistos_d.add(dom)
                        nuevos_d.append(dom)
                    if f"{dom}|{ip}" not in self.por_objetivo and self.args.hermanos_ip:
                        # The IP block already covers it at IP-capable ISPs; a domain order covers the rest.
                        self.preventivo(dom, ip, exp, f"el dominio {dom} figura en DNS pasivo en la IP dedicada {ip} "
                                        f"de la misma operación", solo_dominio=True)
            nuevos_i: List[str] = []
            for dom in dominios + nuevos_d:
                if ("dom", dom) in self.expandidos:
                    continue
                self.expandidos.add(("dom", dom))
                consultas += 1
                codigo, r = self.dns_dominio(dom)
                if codigo != 200:
                    continue
                for item in r.get("ips", []):
                    ip = item["ip"]
                    if f"{dom}|{ip}" in self.por_objetivo:
                        continue
                    if self.ip_dedicada(dom, ip):
                        self.grafo.unir("dom:" + dom, "ip:" + ip, "DNS pasivo: IP dedicada del dominio")
                        if not self.ip_con_expediente_dedicado(ip):
                            self.preventivo(dom, ip, exp, f"el dominio {dom} de la operación resuelve también a la "
                                            f"IP dedicada {ip} (DNS pasivo)", asn=item.get("asn"))
                        if ip not in vistos_i:
                            vistos_i.add(ip)
                            nuevos_i.append(ip)
                    elif dom != raiz:
                        # Shared IP: never an operation node. Only the operation's own domain, by name.
                        self.preventivo(dom, ip, exp, f"el dominio {dom} de la operación figura en la IP compartida "
                                        f"{ip}: solo bloqueo por dominio", asn=item.get("asn"))
            dominios, ips = [], nuevos_i

    def preventivo(self, dom: str, ip: str, exp: dict, motivo: str, asn: Any = None, solo_dominio: bool = False) -> None:
        if f"{dom}|{ip}" in self.por_objetivo:
            return
        ev = [{"tipo": "dns_pasivo", "dominio": dom, "ip": ip, "consulta_min": self.minuto,
               "sha256_respuesta": sha256_hex(json.dumps([dom, ip, self.dns_ip(ip).get("dominios", [])],
                                                         sort_keys=True).encode("utf-8")),
               "vinculo": self.vinculo(dom, exp["host_stream"])}]
        self.crear_expediente(dom, ip, asn, f"infraestructura vinculada a {exp['sitio']} (expediente {exp['id']}): "
                              f"{motivo}. Bloqueo preventivo, sin stream detectado aún.", ev, "preventivo",
                              marca=exp.get("marca"), origen=exp["id"], solo_dominio=solo_dominio)

    def crear_expediente(self, host: str, ip: str, asn: Any, motivo: str, evidencia: List[dict], tipo: str,
                         marca: Optional[str] = None, origen: Optional[str] = None,
                         solo_dominio: bool = False) -> dict:
        riesgo = self.evaluar_riesgo(host, ip)
        plan = self.planificar(host, ip, dict(riesgo, ip_compartida=True) if solo_dominio else riesgo)
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
        self.grafo.unir("dom:" + host, "base:" + dominio_base(host), "mismo dominio base")
        if not riesgo["ip_compartida"]:
            self.grafo.unir("dom:" + host, "ip:" + ip, "IP dedicada")
        self.audit.registrar("expediente_creado", self.minuto, expediente=exp["id"], tipo=tipo, host=host, ip=ip,
                             plan=plan, sello=exp["sello"], ip_compartida=riesgo["ip_compartida"])
        self.notificar_juez(exp)
        return exp

    def buscar_marco(self, exp: dict) -> Tuple[Optional[dict], Optional[str]]:
        """Framework order via the infrastructure graph: an approved (non-preventive) case in the same
        connected component, approved or ratified by a judge who is on duty now."""
        for x in self.expedientes.values():
            if x["estado"] != "aprobado" or x is exp or x.get("tipo") == "preventivo":
                continue
            if not self.grafo.mismo("dom:" + x["host_stream"], "dom:" + exp["host_stream"]):
                continue
            for juez in [x["decision"]["juez_id"]] + x.get("ratificado_por", []):
                if juez in self.de_turno:
                    exp["vinculo_marco"] = self.vinculo(exp["host_stream"], x["host_stream"])
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
                if self.ip_dedicada(cand, ip):
                    self.grafo.unir("dom:" + cand, "ip:" + ip, "DNS pasivo: IP dedicada del dominio")
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
                if exp.get("tipo") != "preventivo":
                    self.seguro(self.expandir, exp)
                if self.args.prediccion and not self.args.sin_adivinar and exp.get("tipo") != "preventivo":
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
            try:
                sigue = self.tick()
            except Exception as err:  # never let one bad response stop the match
                self.audit.registrar("error", self.minuto, error=repr(err))
                sigue = True
            if not sigue:
                break
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
    ap.add_argument("--sin-adivinar", action="store_true", help="no adivinar nombres hermanos (s1->s2, espejo.)")
    ap.add_argument("--sin-expansion", dest="expansion", action="store_false", default=True,
                    help="no expandir la operación por DNS pasivo (grafo)")
    ap.add_argument("--sin-promo", action="store_true", help="no usar cuentas de promoción como aristas del grafo")
    ap.add_argument("--sin-hermanos-ip", dest="hermanos_ip", action="store_false", default=True,
                    help="no abrir expediente por dominio para otros dominios de una IP dedicada")
    ap.add_argument("--juez-auto", type=float, default=None,
                    help="SOLO PRUEBAS: el juez de turno aprueba solo tras N minutos de partido")
    ap.add_argument("--intervalo", type=float, default=0.2, help="segundos reales entre consultas")
    args = ap.parse_args()
    Plataforma(args).correr()


if __name__ == "__main__":
    main()
