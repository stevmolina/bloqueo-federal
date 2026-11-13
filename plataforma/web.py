"""Interfaz web del juez y registro público de transparencia (stdlib only).

- /            Panel del juez (login con usuario y contraseña de demostración).
- /api/estado  Cola de expedientes ordenada (en vivo primero, un lote por sitio u operación).
- /api/decidir Aprobar o rechazar expedientes (solo el juez de turno; la firma la hace la plataforma
               con la clave de ese juez recién después de su aprobación).
- /api/ratificar  El juez entrante ratifica las órdenes marco del turno anterior.
- /expediente/<id>  Vista imprimible del expediente, con verificación del sello.
- /transparencia    Registro público: qué se bloqueó, cuándo, por orden de quién y hasta cuándo.
- /api/auditoria    Verifica la cadena de hashes del registro de auditoría.
"""
import hashlib
import hmac
import html
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

USUARIOS_DEMO = Path(__file__).resolve().parent / "usuarios_demo.json"


def hash_clave(clave: str, sal: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", clave.encode("utf-8"), bytes.fromhex(sal), 100_000).hex()


def resumen_exp(p, x: dict) -> dict:
    r = x["riesgo_colateral"]
    ev = x["evidencia"][0] if x["evidencia"] else {}
    tipos = sorted({(i["tipo"], i["objetivo"]) for i in x["plan"]})
    return {
        "id": x["id"], "tipo": x.get("tipo"), "estado": x["estado"], "sitio": x["sitio"], "host": x["host_stream"],
        "ip": x["ip_servidor"], "org": r.get("organizacion"), "asn": r.get("asn"), "ip_compartida": r["ip_compartida"],
        "riesgo": r["motivo"], "n_ajenos": len(r.get("dominios_ajenos", [])), "ajenos": r.get("dominios_ajenos", [])[:12], "clasificacion": x["clasificacion"],
        "marca": x.get("marca"), "n_evidencia": len(x["evidencia"]), "pagina": ev.get("pagina"),
        "sha256_captura": ev.get("sha256_captura"), "promocion": [q.get("url") for q in ev.get("promocion", [])],
        "bloqueos": [{"tipo": t, "objetivo": o, "proveedores": sorted(i["proveedor"] for i in x["plan"]
                                                                       if i["tipo"] == t and i["objetivo"] == o)}
                     for t, o in tipos],
        "creado_min": x["creado_min"], "espera_min": round(p.minuto - x.get("notificado_min", x["creado_min"]), 2),
        "origen": x.get("origen"), "orden_marco": x.get("orden_marco"), "sello": x["sello"],
        "decision": x.get("decision"), "vence_min": x["vence_min"],
    }


def estado_ordenes(p, x: dict) -> Dict[str, str]:
    """Best state per provider for this case: aplicada > recibida > fallida > rechazada."""
    rango = {"aplicada": 5, "levantada": 4, "vencida": 4, "recibida": 3, "fallida": 2, "rechazada": 1}
    mejor: Dict[str, str] = {}
    for (pid, _), o in p.ordenes.items():
        if o["expediente_id"] == x["id"] and rango.get(o["estado"], 0) > rango.get(mejor.get(pid, ""), 0):
            mejor[pid] = o["estado"]
    return mejor


def web_kpis(p, web) -> dict:
    """Headline numbers for the judge screen, computed from the platform's own state."""
    vivos = [x for x in p.expedientes.values() if x.get("tipo") != "preventivo"]
    bloqueados, tiempos, linea = 0, [], []
    for x in vivos:
        aplicadas = [o.get("aplicada_min") for o in p.ordenes.values()
                     if o["expediente_id"] == x["id"] and o.get("aplicada_min") is not None]
        if aplicadas:
            bloqueados += 1
            primero = x["evidencia"][0].get("minuto", x["creado_min"]) if x["evidencia"] else x["creado_min"]
            tiempos.append(max(0.0, min(aplicadas) - (primero if isinstance(primero, (int, float)) else x["creado_min"])))
            linea.append({"min": round(min(aplicadas), 1), "tipo": "bloqueo", "sitio": x["sitio"]})
        det = x["evidencia"][0].get("minuto") if x["evidencia"] else None
        if isinstance(det, (int, float)):
            linea.append({"min": det, "tipo": "deteccion", "sitio": x["sitio"]})
    import time as _t
    if _t.time() - getattr(web, "_aud_t", 0) > 3:
        from motor import verificar_auditoria
        web._aud = verificar_auditoria(p.audit.ruta)
        web._aud_t = _t.time()
    ok, detalle = getattr(web, "_aud", (True, ""))
    reclamos = getattr(p, "n_reclamos", 0)
    return {"reclamos": reclamos, "vivos": len(vivos), "bloqueados": bloqueados, "linea": sorted(linea, key=lambda e: e["min"]),
            "tiempo_medio": round(sum(tiempos) / len(tiempos), 1) if tiempos else None,
            "auditoria_ok": ok, "auditoria_n": p.audit.n, "auditoria_detalle": detalle}


class Web:
    def __init__(self, plataforma, puerto: int):
        self.p = plataforma
        self.puerto = puerto
        self.sesiones: Dict[str, str] = {}
        datos = json.loads(USUARIOS_DEMO.read_text(encoding="utf-8"))
        self.usuarios = datos["usuarios"]

    def login(self, usuario: str, clave: str) -> Optional[str]:
        u = self.usuarios.get(usuario)
        if not u or not hmac.compare_digest(u["hash"], hash_clave(clave, u["sal"])):
            self.p.audit.registrar("login_fallido", self.p.minuto, usuario=usuario)
            return None
        token = secrets.token_urlsafe(24)
        self.sesiones[token] = u["juez_id"]
        self.p.audit.registrar("login_juez", self.p.minuto, juez_id=u["juez_id"])
        return token

    def estado(self, juez: Optional[str]) -> dict:
        p = self.p
        with p.lock:
            pend = [x for x in p.expedientes.values() if x["estado"] == "pendiente_juez"]
            grupos = sorted(p.grupos_pendientes(pend), key=p.clave_cola)
            cola = [{"preventivo": all(x.get("tipo") == "preventivo" for x in g),
                     "sitio": g[0]["sitio"], "items": [resumen_exp(p, x) for x in sorted(g, key=lambda x: x["creado_min"])]}
                    for g in grupos]
            decididos = sorted((x for x in p.expedientes.values() if x["estado"] != "pendiente_juez"),
                               key=lambda x: -(x["decision"] or {}).get("minuto", 0))
            recientes = [dict(resumen_exp(p, x), proveedores=estado_ordenes(p, x)) for x in decididos[:12]]
            marcos = [x["id"] + " · " + x["sitio"] for x in p.marcos_a_ratificar()] if p.args.orden_marco else []
            nombres = {j["id"]: j.get("nombre", j["id"]) for j in p.jueces_info} if hasattr(p, "jueces_info") else {}
            return {
                "minuto": p.minuto, "fin_min": p.fin_min, "partido": p.partido.get("nombre"),
                "de_turno": p.de_turno, "de_turno_nombres": [nombres.get(j, j) for j in p.de_turno], "juez": juez, "juez_nombre": nombres.get(juez, juez),
                "puede_firmar": bool(juez and juez in p.de_turno),
                "ratificar": marcos if juez in p.de_turno else [],
                "cola": cola, "recientes": recientes,
                "proveedores": [{"id": q["id"], "nombre": q["nombre"], "capacidades": q.get("capacidades", [])}
                                for q in p.proveedores],
                "metricas": {"expedientes": len(p.expedientes), "descartes": len(p.descartes),
                             "aprobados": sum(1 for x in p.expedientes.values() if x["estado"] == "aprobado"),
                             "ordenes_aplicadas": sum(1 for o in p.ordenes.values() if o["estado"] == "aplicada"),
                             **web_kpis(p, self),
                             # Legitimate sites that shared a server with an approved pirate and stayed online
                             # because the platform blocked only the domain.
                             "protegidos": sorted({d for x in p.expedientes.values() if x["estado"] == "aprobado"
                                                   and x["riesgo_colateral"]["ip_compartida"]
                                                   for d in x["riesgo_colateral"].get("dominios_ajenos", [])})},
            }

    # ---- server
    def iniciar(self) -> None:
        web = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _juez(self) -> Optional[str]:
                for c in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = c.strip().partition("=")
                    if k == "sesion":
                        return web.sesiones.get(v)
                return None

            def _enviar(self, codigo: int, cuerpo: Any, tipo: str = "application/json", extra: Optional[dict] = None):
                datos = cuerpo if isinstance(cuerpo, bytes) else (
                    cuerpo.encode("utf-8") if isinstance(cuerpo, str) else
                    json.dumps(cuerpo, ensure_ascii=False).encode("utf-8"))
                self.send_response(codigo)
                self.send_header("Content-Type", tipo + "; charset=utf-8")
                self.send_header("Content-Length", str(len(datos)))
                self.send_header("Cache-Control", "no-store")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(datos)

            def _cuerpo(self) -> dict:
                n = int(self.headers.get("Content-Length", "0") or 0)
                try:
                    return json.loads(self.rfile.read(n) or b"{}")
                except ValueError:
                    return {}

            def do_GET(self) -> None:
                ruta = urlparse(self.path).path
                if ruta == "/":
                    return self._enviar(200, (Path(__file__).resolve().parent / "panel.html").read_text(encoding="utf-8"), "text/html")
                if ruta == "/api/estado":
                    return self._enviar(200, web.estado(self._juez()))
                if ruta == "/transparencia":
                    return self._enviar(200, web.transparencia(), "text/html")
                if ruta.startswith("/expediente/"):
                    return self._enviar(*web.expediente_html(ruta.split("/")[-1]), "text/html")
                if ruta == "/api/auditoria":
                    from motor import verificar_auditoria
                    ok, msg = verificar_auditoria(web.p.audit.ruta)
                    return self._enviar(200, {"integra": ok, "detalle": msg})
                self._enviar(404, {"error": "no existe"})

            def do_POST(self) -> None:
                ruta = urlparse(self.path).path
                c = self._cuerpo()
                if ruta == "/api/login":
                    token = web.login(str(c.get("usuario", "")), str(c.get("clave", "")))
                    if not token:
                        return self._enviar(401, {"error": "usuario o contraseña incorrectos"})
                    return self._enviar(200, {"ok": True}, extra={
                        "Set-Cookie": f"sesion={token}; HttpOnly; SameSite=Strict; Path=/"})
                if ruta == "/api/logout":
                    return self._enviar(200, {"ok": True}, extra={"Set-Cookie": "sesion=; Max-Age=0; Path=/"})
                juez = self._juez()
                if not juez:
                    return self._enviar(401, {"error": "iniciar sesión"})
                if ruta == "/api/decidir":
                    res = []
                    motivo = str(c.get("motivo", ""))[:300]
                    for eid in c.get("aprobar", []):
                        res.append([eid, *web.p.decidir(eid, juez, True, motivo or "aprobado por el juez de turno")])
                    for eid in c.get("rechazar", []):
                        res.append([eid, *web.p.decidir(eid, juez, False, motivo or "rechazado por el juez de turno")])
                    return self._enviar(200, {"resultados": res})
                if ruta == "/api/ratificar":
                    return self._enviar(200, {"ratificados": web.p.ratificar(juez)})
                self._enviar(404, {"error": "no existe"})

        srv = ThreadingHTTPServer(("0.0.0.0", self.puerto), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        print(f"Panel del juez: http://localhost:{self.puerto}/  ·  Transparencia: /transparencia", flush=True)

    # ---- páginas
    def expediente_html(self, eid: str):
        from motor import calcular_sello
        p = self.p
        with p.lock:
            x = p.expedientes.get(eid)
            if not x:
                return 404, "<h1>Expediente inexistente</h1>"
            x = json.loads(json.dumps(x))
            prov = estado_ordenes(p, x)
        integro = calcular_sello(x) == x["sello"]
        e = html.escape
        filas_ev = "".join(
            f"<tr><td>{e(str(v.get('deteccion', v.get('tipo'))))}</td><td>{e(str(v.get('minuto', v.get('consulta_min'))))}</td>"
            f"<td>{e(str(v.get('marca_de_agua', '')))}</td><td><code>{e(str(v.get('sha256_captura') or v.get('sha256_respuesta')))}</code></td></tr>"
            for v in x["evidencia"])
        filas_plan = "".join(f"<tr><td>{e(i['proveedor'])}</td><td>{e(i['tipo'])}</td><td>{e(i['objetivo'])}</td>"
                             f"<td>{e(prov.get(i['proveedor'], '—'))}</td></tr>" for i in x["plan"])
        d = x.get("decision") or {}
        r = x["riesgo_colateral"]
        ajenos = r.get("dominios_ajenos", [])
        if r["ip_compartida"] and ajenos:
            protege = (f"El servidor también aloja {len(ajenos)} sitio{'s' if len(ajenos) > 1 else ''} inocente"
                       f"{'s' if len(ajenos) > 1 else ''}: {e(', '.join(ajenos[:6]))}{' y otros' if len(ajenos) > 6 else ''}. "
                       "Por eso se bloquea solo el dominio y siguen en línea.")
        elif r["ip_compartida"]:
            protege = "No hay datos de quién más usa el servidor, así que se bloquea solo el dominio."
        else:
            protege = "El servidor es solo del pirata: se bloquea su IP y su dominio."
        estado = {"aprobado": "Aprobado y firmado", "rechazado": "Rechazado", "pendiente_juez": "Esperando al juez"}.get(x["estado"], x["estado"])
        firma = (f"{estado} por {e(str(d.get('juez_id')))} en el minuto {e(str(d.get('minuto')))}." if d else estado + ".")
        cuerpo = f"""<p class=k>Expediente {e(x['id'])}</p>
<h1>Bloquear {e(x['host_stream'])}</h1>
<p class="sello{'' if integro else ' mal'}">{'Sello íntegro. Nadie modificó este expediente desde que se creó.' if integro else 'El sello no coincide: este expediente fue modificado.'}</p>
<h2>Qué se pide</h2><p>Bloquear {e(x['host_stream'])} en todos los proveedores hasta el minuto {x['vence_min']} del partido.</p>
<h2>Por qué</h2><p>{'Es un servidor de respaldo del mismo sitio, encontrado antes de que transmita.' if x.get('origen') else 'Transmite la señal oficial del partido sin licencia. Lo prueba su marca de agua.'}</p>
<h2>A quién protege</h2><p>{protege}</p>
<h2>Decisión</h2><p>{firma}</p>
<details><summary>Evidencia técnica</summary>
<p>Servidor {e(x['ip_servidor'])}, {e(str(r.get('organizacion')))} (AS{e(str(r.get('asn')))}).</p>
<table><tr><th>Fuente</th><th>Minuto</th><th>Marca de agua</th><th>SHA-256</th></tr>{filas_ev}</table>
<table><tr><th>Proveedor</th><th>Tipo</th><th>Objetivo</th><th>Estado</th></tr>{filas_plan}</table>
<p>Sello <code>{e(x['sello'])}</code><br>Firma del juez <code>{e(str(d.get('firma_decision', '—')))}</code></p></details>"""
        return 200, PAGINA.format(titulo=e(x["id"]), cuerpo=cuerpo)

    def transparencia(self) -> str:
        p = self.p
        e = html.escape
        with p.lock:
            filas = []
            for x in sorted(p.expedientes.values(), key=lambda x: x["creado_min"]):
                if x["estado"] == "pendiente_juez":
                    continue
                d = x.get("decision") or {}
                tipos = ", ".join(sorted({i["tipo"] for i in x["plan"]}))
                filas.append(f"<tr><td><a href='/expediente/{e(x['id'])}'>{e(x['id'])}</a></td><td>{e(x['host_stream'])}</td>"
                             f"<td>{e(tipos)}</td><td>{e(x['estado'])}</td><td>{e(str(d.get('juez_id', '')))}</td>"
                             f"<td>{e(str(d.get('minuto', '')))}</td><td>{x['vence_min']}</td></tr>")
        cuerpo = ("<h1>Registro público de bloqueos</h1><p>Qué se bloqueó, cuándo, por orden de quién y hasta cuándo. "
                  "Los minutos son minutos de partido.</p><table><tr><th>Expediente</th><th>Sitio</th><th>Tipo</th>"
                  "<th>Estado</th><th>Juez</th><th>Minuto</th><th>Vence</th></tr>" + "".join(filas) + "</table>")
        return PAGINA.format(titulo="Transparencia", cuerpo=cuerpo)


PAGINA = """<!doctype html><html lang=es><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>{titulo} · Bloqueo Federal</title>
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@400;500;600;700&display=swap" rel=stylesheet>
<style>body{{margin:0;font:15px/1.55 Sora,system-ui,sans-serif;color:#191932;background:#f7f7f3}}
.top{{background:#0d0d1a;color:#fff;padding:16px 28px;display:flex;align-items:center;gap:10px;font-weight:600;font-size:18px;letter-spacing:-.02em}}
.top i{{width:28px;height:28px;border-radius:8px;background:#d4f7a6;display:inline-block}}
.w{{max-width:760px;margin:0 auto;padding:48px 32px 64px}}
table{{border-collapse:collapse;width:100%;margin:10px 0;background:#fff;border-radius:16px;overflow:hidden;border:1px solid #e6e6df}}
td,th{{border-bottom:1px solid #e6e6df;padding:9px 12px;text-align:left;font-size:13px}}th{{color:#6b6d85;font-weight:500}}
code{{font-size:11px;word-break:break-all;font-family:ui-monospace,Menlo,monospace}}
h1{{font-size:38px;font-weight:600;letter-spacing:-.03em;line-height:1.15;margin:0 0 18px}}h2{{font-size:15px;font-weight:500;color:#7a7c92;margin:26px 0 4px}}h2+p{{margin-top:0;font-size:17px}}
.sello{{background:#d4f7a6;padding:14px 18px;border-radius:16px}}.sello.mal{{background:#ffd9d5}}.k{{color:#7a7c92;margin:0 0 6px}}details{{margin-top:30px;color:#46475e}}summary{{cursor:pointer;font-weight:500}}a{{color:#191932}}
</style><body><div class=top><i></i>Bloqueo Federal</div><div class=w>{cuerpo}</div></body></html>"""

PANEL_HTML = (Path(__file__).resolve().parent / "panel.html").read_text(encoding="utf-8")
