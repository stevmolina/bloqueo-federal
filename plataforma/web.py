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
        "riesgo": r["motivo"], "n_ajenos": len(r.get("dominios_ajenos", [])), "clasificacion": x["clasificacion"],
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
                    return self._enviar(200, PANEL_HTML, "text/html")
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
        cuerpo = f"""<h1>Expediente {e(x['id'])}</h1>
<p class=sello>{'✅ Sello íntegro' if integro else '❌ SELLO NO COINCIDE: el expediente fue alterado'} · <code>{e(x['sello'])}</code></p>
<h2>Qué se pide</h2><p>Bloquear <b>{e(x['host_stream'])}</b> (servidor {e(x['ip_servidor'])}, {e(str(r.get('organizacion')))} AS{e(str(r.get('asn')))})
hasta el minuto {x['vence_min']} del partido.</p>
<h2>Por qué</h2><p>{e(x['clasificacion'])}.</p>
<p><b>Riesgo colateral:</b> {e(r['motivo'])}. {'Se bloquea solo por dominio para no afectar sitios legítimos.' if r['ip_compartida'] else 'IP dedicada: se bloquea por IP y por dominio.'}</p>
{f"<p><b>Origen:</b> infraestructura vinculada al expediente {e(x['origen'])} (bloqueo preventivo).</p>" if x.get('origen') else ''}
{f"<p><b>Orden marco:</b> ampliación de {e(x['orden_marco'])}.</p>" if x.get('orden_marco') else ''}
<h2>Evidencia</h2><table><tr><th>Fuente</th><th>Minuto</th><th>Marca de agua</th><th>SHA-256</th></tr>{filas_ev}</table>
<h2>Órdenes por proveedor</h2><table><tr><th>Proveedor</th><th>Tipo</th><th>Objetivo</th><th>Estado</th></tr>{filas_plan}</table>
<h2>Decisión</h2><p>{e(x['estado'])} · {e(str(d.get('juez_id', '—')))} ({e(str(d.get('juzgado_id', '')))}) en el minuto {e(str(d.get('minuto', '—')))}<br>
Firma: <code>{e(str(d.get('firma_decision', '—')))}</code></p>"""
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
<title>{titulo}</title><style>body{{font:15px system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 14px;color:#1b2430}}
table{{border-collapse:collapse;width:100%;margin:8px 0}}td,th{{border:1px solid #d5dbe3;padding:5px 7px;text-align:left;font-size:13px}}
code{{font-size:11px;word-break:break-all}}h1{{font-size:22px}}h2{{font-size:16px;margin-top:20px}}.sello{{background:#f3f6fa;padding:8px;border-radius:6px}}
</style><body>{cuerpo}</body></html>"""

PANEL_HTML = r"""<!doctype html><html lang=es><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Juez de turno · Bloqueos en vivo</title>
<style>
:root{--az:#1d4ed8;--ro:#b91c1c;--ve:#15803d;--gr:#64748b;--bg:#f1f5f9}
*{box-sizing:border-box}body{margin:0;font:15px system-ui,sans-serif;background:var(--bg);color:#0f172a}
header{background:#0f172a;color:#fff;padding:10px 16px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
header b{font-size:17px}.pill{background:#1e293b;border-radius:99px;padding:3px 10px;font-size:13px}
.ok{background:#166534}.no{background:#991b1b}main{max-width:1100px;margin:auto;padding:14px;display:grid;grid-template-columns:2fr 1fr;gap:14px}
@media(max-width:820px){main{grid-template-columns:1fr}}
.card{background:#fff;border-radius:10px;padding:14px;box-shadow:0 1px 3px #0002;margin-bottom:12px}
.vivo{border-left:6px solid var(--ro)}.prev{border-left:6px solid #f59e0b}
.item{border-top:1px solid #e2e8f0;padding:8px 0;display:grid;grid-template-columns:24px 1fr;gap:8px}
.tag{display:inline-block;font-size:11px;border-radius:4px;padding:1px 6px;margin-right:4px;color:#fff}
.t-vivo{background:var(--ro)}.t-prev{background:#d97706}.t-ip{background:var(--az)}.t-dom{background:#7c3aed}.t-safe{background:var(--ve)}.t-warn{background:#b45309}
small{color:var(--gr)}button{font:inherit;border:0;border-radius:8px;padding:10px 16px;cursor:pointer;color:#fff}
.ap{background:var(--ve);font-weight:600}.re{background:var(--ro)}.sec{background:#475569}
.acciones{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}h2{font-size:15px;margin:4px 0 10px}
.rat{background:#fef3c7;border:2px solid #f59e0b}code{font-size:11px}
input{font:inherit;padding:10px;border:1px solid #cbd5e1;border-radius:8px;width:100%;margin:6px 0}
#login{max-width:360px;margin:60px auto}.vacia{color:var(--gr);text-align:center;padding:30px}
.prov{font-size:12px}.prov span{margin-right:8px}.d{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:3px}.dg{background:#16a34a}.dr{background:#dc2626}.dy{background:#eab308}a{color:var(--az)}
</style>
<header><b>Bloqueos en vivo · Juez de turno</b><span class=pill id=min>—</span><span class=pill id=turno>—</span>
<span id=quien class=pill>—</span><span style="flex:1"></span><a style="color:#93c5fd" href="/transparencia" target=_blank>Registro público</a>
<button class=sec id=salir style="padding:5px 10px;display:none">Salir</button></header>
<div id=login class=card style="display:none"><h2>Ingreso del juez</h2>
<input id=u placeholder="Usuario" autocomplete=username><input id=c type=password placeholder="Contraseña" autocomplete=current-password>
<button class=ap id=entrar style="width:100%">Entrar</button><p id=err style="color:var(--ro)"></p></div>
<main id=app style="display:none"><section><div id=rat></div><div id=cola></div></section>
<aside><div class=card><h2>Órdenes recientes</h2><div id=rec></div></div><div class=card><h2>Resumen</h2><div id=met></div>
<p><small>Atajo: <b>A</b> aprueba el primer lote completo.</small></p></div></aside></main>
<script>
const $=id=>document.getElementById(id);let est=null,vistos=new Set(),primero=true,desmarcados=new Set();
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(r,b){const o=b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{};const x=await fetch(r,o);return [x.status,await x.json()]}
function bip(){try{const a=new AudioContext(),o=a.createOscillator();o.frequency.value=880;o.connect(a.destination);o.start();o.stop(a.currentTime+.15)}catch(e){}}
$('entrar').onclick=async()=>{const[s,r]=await api('/api/login',{usuario:$('u').value,clave:$('c').value});
 if(s!==200){$('err').textContent=r.error;return}$('c').value='';if('Notification'in window)Notification.requestPermission();tick()};
$('c').onkeydown=e=>{if(e.key==='Enter')$('entrar').click()};
$('salir').onclick=async()=>{await api('/api/logout',{});tick()};
async function decidir(apr,rec){await api('/api/decidir',{aprobar:apr,rechazar:rec});tick()}
function aprobarLote(i){const g=est.cola[i];const ids=[...document.querySelectorAll(`input[data-g="${i}"]`)];
 decidir(ids.filter(x=>x.checked).map(x=>x.value),ids.filter(x=>!x.checked).map(x=>x.value))}
function rechazarLote(i){decidir([],est.cola[i].items.map(x=>x.id))}
document.onkeydown=e=>{if(e.key.toLowerCase()==='a'&&est&&est.puede_firmar&&est.cola.length&&document.activeElement.tagName!=='INPUT')aprobarLote(0)};
function item(x,i){const ip=x.bloqueos.map(b=>`<span class="tag ${b.tipo==='ip'?'t-ip':'t-dom'}">${b.tipo==='ip'?'IP':'Dominio'}</span>${esc(b.objetivo)} <small>(${b.proveedores.length} prov.)</small>`).join('<br>');
 return `<div class=item><input type=checkbox ${desmarcados.has(x.id)?'':'checked'} data-g="${i}" value="${esc(x.id)}" onchange="this.checked?desmarcados.delete(this.value):desmarcados.add(this.value)">
 <div><span class="tag ${x.tipo==='preventivo'?'t-prev':'t-vivo'}">${x.tipo==='preventivo'?'PREVENTIVO':'EN VIVO'}</span>
 <b>${esc(x.host)}</b> <small>· ${esc(x.ip)} · ${esc(x.org||'')} · <a href="/expediente/${esc(x.id)}" target=_blank>${esc(x.id)}</a></small><br>
 <small>${esc(x.clasificacion)}</small><br>
 <span class="tag ${x.ip_compartida?'t-warn':'t-safe'}">${x.ip_compartida?'IP COMPARTIDA':'IP DEDICADA'}</span><small>${esc(x.riesgo)}</small><br>
 ${ip}<br><small>Evidencia: ${x.n_evidencia} · sello <code>${esc(x.sello.slice(0,16))}…</code> · espera ${x.espera_min} min</small></div></div>`}
function render(){const s=est;$('min').textContent=`Minuto ${s.minuto.toFixed(1)} / ${s.fin_min}`;
 $('turno').textContent='De turno: '+(s.de_turno_nombres.join(', ')||'—');
 $('quien').textContent=s.juez?(s.puede_firmar?'Firmando: ':'Fuera de turno · ')+s.juez_nombre:'—';$('quien').className='pill '+(s.puede_firmar?'ok':'no');
 $('rat').innerHTML=s.ratificar.length?`<div class="card rat"><h2>Cambio de turno: ratificar ${s.ratificar.length} órdenes marco</h2>
 <small>${s.ratificar.map(esc).join('<br>')}</small><div class=acciones><button class=ap onclick="api('/api/ratificar',{}).then(tick)">Ratificar todas</button></div></div>`:'';
 $('cola').innerHTML=s.cola.length?s.cola.map((g,i)=>`<div class="card ${g.preventivo?'prev':'vivo'}">
 <h2>${i===0?'▶ ':''}${esc(g.sitio)} <small>· ${g.items.length} expediente(s)</small></h2>${g.items.map(x=>item(x,i)).join('')}
 <div class=acciones>${s.puede_firmar?`<button class=ap onclick="aprobarLote(${i})">Aprobar y firmar seleccionados</button>
 <button class=re onclick="rechazarLote(${i})">Rechazar todo</button>`:'<small>Solo el juez de turno puede firmar.</small>'}</div></div>`).join('')
 :'<div class="card vacia">Sin expedientes pendientes.</div>';
 $('rec').innerHTML=s.recientes.map(x=>`<div style="margin-bottom:8px"><a href="/expediente/${esc(x.id)}" target=_blank>${esc(x.id)}</a> ${esc(x.host)}
 <small>${esc(x.estado)}</small><div class=prov>${Object.entries(x.proveedores).map(([p,e])=>`<span><i class="d ${e==='aplicada'?'dg':e==='fallida'||e==='rechazada'?'dr':'dy'}"></i>${esc(p)}</span>`).join('')}</div></div>`).join('')||'<small>—</small>';
 const m=s.metricas;$('met').innerHTML=`<div style="font-size:30px;font-weight:700;color:#15803d">${m.protegidos.length}</div><div style="margin-bottom:6px"><b>sitios legítimos protegidos</b><br><small>Comparten servidor con un pirata y siguen en línea: se bloqueó solo el dominio.</small><br><small style="color:#15803d">${m.protegidos.slice(0,6).map(esc).join(' · ')}${m.protegidos.length>6?' …':''}</small></div><small>Expedientes ${m.expedientes} · aprobados ${m.aprobados} · descartados ${m.descartes} · órdenes aplicadas ${m.ordenes_aplicadas}</small>`}
async function tick(){const[st,s]=await api('/api/estado');est=s;
 $('login').style.display=s.juez?'none':'block';$('app').style.display=s.juez?'grid':'none';$('salir').style.display=s.juez?'inline':'none';
 if(!s.juez){$('min').textContent=`Minuto ${s.minuto.toFixed(1)}`;return}
 const nuevos=s.cola.flatMap(g=>g.items).filter(x=>!vistos.has(x.id));nuevos.forEach(x=>vistos.add(x.id));
 if(nuevos.length&&!primero&&s.puede_firmar){bip();document.title=`(${s.cola.length}) Juez de turno`;
  if(window.Notification&&Notification.permission==='granted')new Notification('Nuevo expediente',{body:nuevos.map(x=>x.host).join(', ')})}
 if(!s.cola.length)document.title='Juez de turno';primero=false;
 render()}
setInterval(tick,1000);tick();
</script></html>"""
