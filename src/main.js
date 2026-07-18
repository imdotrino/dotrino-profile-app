/**
 * dotrino_profile — perfil + calificación + validación de firma (web-of-trust).
 *
 * Modos según el #fragment (nunca llega al server, no indexable):
 *   #<pubkey>            → calificar al sujeto del link (mode="edit").
 *   #p=<pk>&name=&since= → idem, con datos extra.
 *   #v=<payload>         → VALIDAR: verifica la firma del contenido (ECDSA P-256)
 *                          y, en el mismo paso, muestra el perfil + reputación
 *                          del remitente (reviews) con opción de calificarlo.
 *   (sin hash)           → tu propio perfil (mode="self").
 *
 * Reutiliza @dotrino/identity + @dotrino/profile + @dotrino/reputation. La
 * verificación es client-side (solo necesita la clave PÚBLICA, que va en el link).
 */
import { Identity } from '@dotrino/identity'
import { avatarDataUri } from '@dotrino/identity/capabilities'
import { createVaultReputation, canonicalStringify } from '@dotrino/reputation'
import { createVaultProfileProvider } from '@dotrino/profile'
import '@dotrino/profile' // registra el custom element <dotrino-profile>
import '@dotrino/topbar'  // barra superior estándar (marca+volver+idioma+perfil+support)
import jsQR from 'jsqr' // lector de QR client-side (misma lib que dotrino-qrreader)
import { qrSvg } from './qr.js' // generador de QR como SVG (emparejamiento self-vault)

const mount = document.getElementById('app')
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
const showState = (title, html = '') =>
  (mount.innerHTML = `<div class="state">${title ? `<h1>${esc(title)}</h1>` : ''}${html}</div>`)

function b64urlDecode(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  try {
    return decodeURIComponent(atob(s).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join(''))
  } catch { return atob(s) }
}
function b64urlEncode(str) {
  const b64 = btoa(String.fromCharCode(...new TextEncoder().encode(str)))
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/* ── verificación de firma — MISMO esquema que el vault (ECDSA P-256 + SHA-256
   sobre canonicalStringify, firma = base64 de r||s crudos). Solo clave pública. */
const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' }
const SIGN = { name: 'ECDSA', hash: { name: 'SHA-256' } }
const b64ToBuf = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)).buffer
async function verifySig(pubkeyStr, data, sigB64) {
  if (!pubkeyStr || !sigB64) return false
  try {
    const pub = await crypto.subtle.importKey('jwk', JSON.parse(pubkeyStr), ECDSA, true, ['verify'])
    return await crypto.subtle.verify(SIGN, pub, b64ToBuf(sigB64), new TextEncoder().encode(canonicalStringify(data)))
  } catch { return false }
}

function parseHash() {
  const h = location.hash.replace(/^#/, '').trim()
  if (!h) return { mode: 'self' }
  if (h === 'myvault') return { mode: 'selfvault' }
  if (h === 'vault') return { mode: 'vault' }
  if (h.startsWith('vault=')) { try { return { mode: 'vault', qr: JSON.parse(b64urlDecode(h.slice(6))) } } catch { return { mode: 'vault' } } }
  if (h.startsWith('v=')) {
    try { return { mode: 'validate', payload: JSON.parse(b64urlDecode(h.slice(2))) } } catch { return { mode: 'invalid' } }
  }
  if (h.includes('=')) {
    const q = new URLSearchParams(h)
    const p = q.get('p') || q.get('pubkey')
    if (!p) return { mode: 'invalid' }
    return { mode: 'rate', pubkey: b64urlDecode(p), name: q.get('name') ? b64urlDecode(q.get('name')) : '', since: q.get('since') || '' }
  }
  return { mode: 'rate', pubkey: b64urlDecode(h), name: '', since: '' }
}

async function connectProvider() {
  const id = await Identity.connect()
  let reputation = null
  try { reputation = createVaultReputation(id) } catch { /* sin reputación: el perfil igual abre */ }
  return { id, provider: createVaultProfileProvider({ identity: id, reputation }) }
}

function makeProfile({ pubkey, name, since, mode, modal, manage }) {
  const el = document.createElement('dotrino-profile')
  if (modal) el.setAttribute('modal', '')
  if (manage) el.setAttribute('manage', '') // crear perfil habilitado SOLO aquí (profile.dotrino.com)
  el.setAttribute('mode', mode)
  el.setAttribute('lang', 'auto')
  el.setAttribute('pubkey', pubkey)
  if (name) el.setAttribute('name', name)
  if (since) el.setAttribute('since', since)
  el.addEventListener('cc-profile-close', () => { window.location.href = 'https://dotrino.com' })
  return el
}

/* ── Conectar este dispositivo a la bóveda del usuario (dotrino-vault) — #vault ── */
function injectVaultStyles () {
  if (document.getElementById('vault-css')) return
  const s = document.createElement('style'); s.id = 'vault-css'
  s.textContent = `
    .vault-wrap { max-width: 560px; margin: 0 auto; text-align: left; }
    .vault-wrap textarea { width: 100%; box-sizing: border-box; font-family: ui-monospace, monospace; font-size: 13px; padding: 10px; border: 1px solid #ccc; border-radius: 8px; resize: vertical; }
    .vault-wrap .btn { display: inline-block; margin-top: 12px; padding: 10px 18px; border: 0; border-radius: 999px; background: #1a73e8; color: #fff; font-size: 15px; cursor: pointer; }
    .vault-wrap .btn[disabled] { opacity: .5; cursor: default; }
    .vault-wrap .btn.danger { background: #d93025; }
    .vault-wrap .banner { margin: 14px 0; padding: 10px 14px; border-radius: 8px; background: #eef2ff; }
    .vault-wrap .banner.ok { background: #e6f4ea; color: #137333; }
    .vault-wrap .banner.bad { background: #fce8e6; color: #c5221f; }
    .vault-wrap .sas-box { margin: 16px 0; padding: 16px; border: 2px solid #1a73e8; border-radius: 12px; text-align: center; }
    .vault-wrap .sas-box .sas { font-size: 40px; letter-spacing: 8px; font-weight: 700; font-family: ui-monospace, monospace; margin: 8px 0; }
    .vault-wrap .muted { color: #777; font-size: 13px; }
    .vault-wrap .vault-info { list-style: none; padding: 0; }
    .vault-wrap .vault-info li { padding: 4px 0; }
    .vault-wrap .btn.ghost { background: #eef2ff; color: #1a73e8; }
    .vault-wrap .scanrow { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .vault-wrap .scanbox video { width: 100%; max-width: 360px; border-radius: 10px; background: #000; display: block; margin: 8px 0; }
    .vault-wrap details > summary { cursor: pointer; margin-top: 10px; color: #777; }
    /* Barra superior estándar del ecosistema: <dotrino-topbar> (@dotrino/topbar),
       tematizada en CLARO para esta página. La marca a medida va por slot. */
    #app:has(.vault-page) { padding: 0; align-items: stretch; }
    .vault-page { width: 100%; min-height: 100vh; display: flex; flex-direction: column; }
    .vault-topbar {
      position: sticky; top: 0; z-index: 50;
      --dotrino-topbar-bg: #fff; --dotrino-topbar-border: #e3e9ed;
      --dotrino-topbar-text: #181c1e; --dotrino-topbar-muted: #4a5560;
      --dotrino-topbar-accent: #00658c;
    }
    .vault-page .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
    .vault-page .brand-logo { width: 36px; height: 36px; border-radius: 9px; }
    .vault-page .brand-text { display: flex; flex-direction: column; line-height: 1.1; min-width: 0; }
    .vault-page .brand-name { font-weight: 700; font-size: 1.15rem; color: #181c1e; }
    .vault-page .brand-tag { font-size: .72rem; color: #4a5560; }
    .vault-page .vault-main { flex: 1; display: flex; align-items: flex-start; justify-content: center; padding: 1.2rem 1rem; }
    .vault-page .vault-card { max-width: 560px; width: 100%; text-align: left; }
    .vault-page .vault-card h1 { font-size: 1.3rem; color: #181c1e; margin: 0 0 1rem; }
    /* Sección de PIN (inline en la página, no popup) */
    .pin-box { margin-top: 1.2rem; padding: 1rem 1.1rem; border: 1px solid #e3e9ed; border-radius: 14px; background: #fff; }
    .pin-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; }
    .pin-title { font-weight: 700; color: #181c1e; }
    .pin-box .btn { display: inline-flex; align-items: center; padding: 9px 14px; border: 0; border-radius: 999px; background: #1a73e8; color: #fff; font-size: 14px; cursor: pointer; }
    .pin-box .btn.ghost { background: #eef2ff; color: #1a73e8; }
    .pin-box .btn.danger { background: #d93025; color: #fff; }
    .pin-box .btn[disabled] { opacity: .5; cursor: default; }
    .pf-nameform, .pf-confirm { display: flex; gap: 8px; align-items: center; margin-top: 12px; flex-wrap: wrap; }
    .pf-nameform input { flex: 1 1 auto; padding: 9px 11px; border: 1px solid #cfd8de; border-radius: 8px; font-size: 14px; }
    .pf-confirm span { flex: 1 1 100%; font-size: .85rem; color: #b3261e; }
    /* ── Self-vault (#myvault): este dispositivo ES la bóveda ── */
    .sv-status { display: inline-block; margin: 4px 0 12px; font-size: .82rem; color: #137333; }
    .sv-status.bad { color: #b3261e; }
    .sv-block { margin: 14px 0; }
    .sv-setup { background: #f4f7f9; border: 1px solid #e3e9ed; border-radius: 12px; padding: 14px; }
    .sv-setup pre, .sv-qr-code pre { background: #0e1116; color: #7dd3fc; padding: 10px; border-radius: 8px; overflow-x: auto; font-size: .78rem; word-break: break-all; margin: 8px 0; }
    .sv-qr-wrap { background: #fff; padding: 10px; border-radius: 10px; display: inline-block; margin: 8px 0; border: 1px solid #e3e9ed; }
    .sv-qr-wrap svg { width: 200px; height: 200px; display: block; }
    .sv-pending { margin-top: 12px; padding-top: 12px; border-top: 1px dashed #cfd8de; }
    .sv-pair-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
    .sv-code-input { flex: 1 1 120px; background: #fff; color: #181c1e; border: 1px solid #cfd8de; border-radius: 10px; padding: 10px 12px; font-size: 1.1rem; letter-spacing: 2px; }
    .sv-machine-list { display: flex; flex-direction: column; gap: 8px; margin-top: 8px; }
    .sv-machine-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; background: #f4f7f9; border: 1px solid #e3e9ed; border-radius: 10px; padding: 10px 14px; }
    .sv-machine-name { word-break: break-all; display: inline-flex; align-items: center; gap: 8px; }
    .sv-mdot { width: 9px; height: 9px; border-radius: 50%; background: #cfd8de; display: inline-block; flex: none; }
    .sv-mdot.on { background: #34a853; } .sv-mdot.off { background: #ea4335; }
    .sv-link-row { margin-top: 14px; }
    .sv-link-row a { color: #00658c; font-weight: 600; text-decoration: none; }
    .sv-toggle-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; margin: 10px 0; padding: 12px 14px; border: 1px solid #e3e9ed; border-radius: 12px; background: #fff; }`
  document.head.appendChild(s)
}

async function vaultFingerprint (jwkStr) {
  try {
    const jwk = JSON.parse(jwkStr)
    const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalStringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })))
    return [...new Uint8Array(h)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('')
  } catch { return '????????' }
}

// Extrae el objeto de emparejamiento de un texto: URL profile.dotrino.com/#vault=… o JSON crudo.
function extractPayload (text) {
  if (!text) return null
  text = String(text).trim()
  const i = text.indexOf('#vault=')
  if (i >= 0) { try { return JSON.parse(b64urlDecode(text.slice(i + 7))) } catch { return null } }
  try { const o = JSON.parse(text); return (o && o.iss && o.token) ? o : null } catch { return null }
}

// Decodifica un QR desde una imagen (archivo). Devuelve el texto o null.
function decodeQrFromImage (file) {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight
      try { const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0); const d = ctx.getImageData(0, 0, c.width, c.height); resolve(jsQR(d.data, d.width, d.height)?.data || null) }
      catch { resolve(null) }
      URL.revokeObjectURL(img.src)
    }
    img.onerror = () => resolve(null)
    img.src = URL.createObjectURL(file)
  })
}

// Escáner con cámara: muestra el video en `host`, devuelve el texto del QR (o null si cancelan/falla).
function scanWithCamera (host) {
  return new Promise((resolve) => {
    let stream = null, raf = null, done = false
    const stop = (val) => { if (done) return; done = true; if (raf) cancelAnimationFrame(raf); if (stream) stream.getTracks().forEach(t => t.stop()); host.innerHTML = ''; resolve(val) }
    host.innerHTML = '<div class="scanbox"><video playsinline muted></video><div><button id="scancancel" class="btn ghost">Cancelar</button></div></div>'
    const video = host.querySelector('video')
    host.querySelector('#scancancel').onclick = () => stop(null)
    const c = document.createElement('canvas'); const ctx = c.getContext('2d')
    const tick = () => {
      if (done) return
      if (video.readyState >= 2 && video.videoWidth) {
        c.width = video.videoWidth; c.height = video.videoHeight; ctx.drawImage(video, 0, 0, c.width, c.height)
        try { const d = ctx.getImageData(0, 0, c.width, c.height); const r = jsQR(d.data, d.width, d.height); if (r?.data) return stop(r.data) } catch {}
      }
      raf = requestAnimationFrame(tick)
    }
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
      .then((s) => { stream = s; video.srcObject = s; return video.play().catch(() => {}) })
      .then(() => { raf = requestAnimationFrame(tick) })
      .catch(() => { host.innerHTML = '<div class="banner bad">No se pudo abrir la cámara. Probá «Abrir imagen/archivo» o pegá el código.</div>'; resolve(null) })
  })
}

function vaultShell (title, inner, tag = 'Tu identidad') {
  mount.innerHTML = `<div class="vault-page">
    <dotrino-topbar class="vault-topbar" brand-href="https://dotrino.com/"
      support-repo="imdotrino/dotrino_profile" support-discord="https://discord.gg/D648uq7cth" profile>
      <div slot="brand" class="brand"><img class="brand-logo" src="/images/imagoWBG.png" alt="" /><div class="brand-text"><span class="brand-name">Dotrino</span><span class="brand-tag">${esc(tag)}</span></div></div>
    </dotrino-topbar>
    <main class="vault-main"><div class="vault-card">${title ? `<h1>${esc(title)}</h1>` : ''}${inner}</div></main>
  </div>`
  decorateProfileButton()
}

// El botón de perfil del topbar (§6.1) muestra el AVATAR del perfil activo y abre
// el GESTOR de perfiles (esta app ES el hub de identidad): switcher + proteger con
// PIN + "ver mi perfil". El topbar emite 'dotrino-profile'; el avatar va por atributo.
async function decorateProfileButton () {
  const tb = mount.querySelector('dotrino-topbar'); if (!tb) return
  // profile.dotrino.com ES el hub de identidad: el avatar lleva a la página del
  // perfil (donde está todo inline), en vez de abrir un popup redundante.
  tb.addEventListener('dotrino-profile', () => { location.href = '/' })
  try {
    const id = await Identity.connect()
    const cur = await id.currentProfile()
    // Preferir la FOTO subida del perfil activo (me.avatar, data-URI); si no se
    // subió ninguna, caer al identicon determinista del pubkey.
    let avatar = null
    try { const me = await id.getMe(); if (me && me.avatar) avatar = me.avatar } catch (_) {}
    if (!avatar && cur?.pubkey) avatar = avatarDataUri(cur.pubkey, { size: 72 })
    if (avatar) tb.setAttribute('avatar', avatar)
  } catch (_) { /* deja el ícono genérico */ }
}

// Sección de PIN INLINE en la página (NO en popup). El PIN protege el perfil
// activo SOLO en este dispositivo. Cambiar/crear/renombrar perfil lo hace el
// componente <dotrino-profile mode="self" manage> (switcher integrado); aquí solo
// va lo que es exclusivo de esta página: el candado por PIN.
async function renderPinSection (host) {
  let id
  try { id = await Identity.connect() } catch { return }
  const lock = await id.profileLockStatus?.().catch(() => null) || { protected: false }
  host.innerHTML = `
    <div class="pin-box">
      <div class="pin-row">
        <span class="pin-title">🔒 Protección con PIN</span>
        <button class="btn ghost" id="pin-toggle">${lock.protected ? 'Quitar el PIN' : 'Proteger con PIN'}</button>
      </div>
      <p class="muted" style="font-size:12.5px;margin:6px 0 0">Protege el perfil activo <strong>solo en este dispositivo</strong> (no se comparte ni se sincroniza). Se pide una vez por pestaña; refrescar no lo vuelve a pedir.</p>
      <div id="pf-form"></div>
    </div>`
  host.querySelector('#pin-toggle').onclick = () => {
    if (lock.protected) {
      confirmDelete(host, null, async () => { await id.removeProfilePassword(); location.reload() },
        '¿Quitar el PIN de este perfil en este dispositivo?', 'Quitar el PIN')
    } else {
      pinForm(host, async (pin) => { await id.setProfilePassword(pin); location.reload() })
    }
  }
}

// Formulario inline de PIN (candado local): pide el PIN dos veces.
function pinForm (overlay, onSubmit) {
  const host = overlay.querySelector('#pf-form')
  host.innerHTML = `<div class="pf-nameform" style="flex-wrap:wrap">
    <input id="pf-pin1" type="password" inputmode="numeric" maxlength="64" placeholder="PIN (mín. 4)" />
    <input id="pf-pin2" type="password" inputmode="numeric" maxlength="64" placeholder="Repite el PIN" />
    <button class="btn" id="pf-pingo">Proteger</button>
    <span class="muted" id="pf-pinerr" style="flex-basis:100%"></span></div>`
  const p1 = host.querySelector('#pf-pin1'); const p2 = host.querySelector('#pf-pin2')
  const err = host.querySelector('#pf-pinerr'); p1.focus()
  const go = async () => {
    err.textContent = ''
    if (p1.value.length < 4) { err.textContent = 'Mínimo 4 caracteres.'; return }
    if (p1.value !== p2.value) { err.textContent = 'No coinciden.'; return }
    host.querySelector('#pf-pingo').disabled = true
    try { await onSubmit(p1.value) } catch (e) { err.textContent = e.message; host.querySelector('#pf-pingo').disabled = false }
  }
  host.querySelector('#pf-pingo').onclick = go
  p2.onkeydown = (e) => { if (e.key === 'Enter') go() }
}

// Confirmación inline de borrado (sin confirm() del navegador).
function confirmDelete (overlay, btn, onYes, msg = '¿Borrar este perfil y todos sus datos? No se puede deshacer.', yes = 'Borrar') {
  const host = overlay.querySelector('#pf-form')
  host.innerHTML = `<div class="pf-confirm"><span>${esc(msg)}</span><button class="btn danger" id="pf-yes">${esc(yes)}</button><button class="btn ghost" id="pf-no">Cancelar</button></div>`
  host.querySelector('#pf-no').onclick = () => { host.innerHTML = '' }
  host.querySelector('#pf-yes').onclick = async () => { host.querySelector('#pf-yes').disabled = true; await onYes() }
}

async function vaultMode (prefillQr) {
  injectVaultStyles()
  let id
  try { id = await Identity.connect() } catch {
    showState('Tu bóveda', '<p>No se pudo conectar tu identidad. Recarga e inténtalo de nuevo.</p>'); return
  }
  // Si venimos de elegir/crear un perfil para esta bóveda (se cambió de perfil y la página
  // recargó), retomamos el emparejamiento con el perfil ya activo, sin volver a preguntar.
  let intentQr = null
  try { const r = sessionStorage.getItem('cc-pair-intent'); if (r) { sessionStorage.removeItem('cc-pair-intent'); intentQr = JSON.parse(r) } } catch (_) {}
  const status = intentQr ? { paired: false } : await id.vaultStatus().catch(() => ({ paired: false }))
  // Cert de dispositivo VENCIDO = ya no estás conectado (el vault rechaza todo con
  // "no autorizado"): tratarlo como no emparejado, con aviso, y ofrecer re-conectar.
  const expired = status.paired && status.exp && status.exp <= Date.now()

  if (status.paired && !expired) {
    const fp = await vaultFingerprint(status.master)
    vaultShell('Tu bóveda', `<div class="vault-wrap">
      <div class="banner ok">✓ Este dispositivo está conectado a tu bóveda.</div>
      <ul class="vault-info">
        <li>Dispositivo: <code>${esc(status.deviceId)}</code></li>
        <li>Bóveda (huella): <code>${esc(fp)}</code></li>
        <li>Permisos: <code>${esc((status.scope || []).join(', '))}</code></li>
        ${status.exp ? `<li>Conexión válida hasta: <code>${esc(new Date(status.exp).toLocaleString())}</code></li>` : ''}
      </ul>
      <h2 style="font-size:16px;margin:18px 0 6px">Tus dispositivos</h2>
      <div id="devlist" class="muted">Cargando…</div>
    </div>`)
    // Lista (solo lectura) de dispositivos enrolados; desconectar/revocar es desde el PC.
    id.listVaultDevices().then(({ devices }) => {
      const box = document.getElementById('devlist'); if (!box) return
      if (!devices?.length) { box.textContent = '—'; return }
      box.innerHTML = '<ul class="vault-info">' + devices.map((d) => {
        const me = d.deviceId === status.deviceId ? ' <strong>(este)</strong>' : ''
        const exp = d.exp ? ' · expira ' + new Date(d.exp).toLocaleDateString() : ''
        return `<li>· <code>${esc(d.deviceId || '????')}</code>${me} ${esc(d.label || '')}<span class="muted">${esc(exp)}</span></li>`
      }).join('') + '</ul>'
    }).catch((e) => {
      const box = document.getElementById('devlist'); if (!box) return
      // Distinguir "no autorizado" (cert rechazado/revocado) de "vault apagado".
      box.textContent = /no autorizado/i.test(e?.message || '')
        ? 'El vault rechazó este dispositivo (' + e.message + '). Vuelve a conectarlo con `dotrino-vault pair`.'
        : 'No se pudo cargar (¿el vault está encendido?).'
    })
    return
  }

  vaultShell('Conectar a tu bóveda', `<div class="vault-wrap">
    ${expired ? '<div class="banner bad">Tu conexión con la bóveda <strong>venció</strong> (' + esc(new Date(status.exp).toLocaleDateString()) + '). Vuelve a conectar este dispositivo.</div>' : ''}
    <p>Conecta este navegador a tu <strong>bóveda</strong> (el programa <code>dotrino-vault</code> en tu PC),
       para que tu información viva en tu propio servidor. En tu PC ejecuta <code>dotrino-vault pair</code> y
       <strong>escaneá el QR</strong>, abrí su imagen/archivo, o pegá el código:</p>
    <div class="scanrow">
      <button id="scan" class="btn">📷 Escanear QR</button>
      <button id="openfile" class="btn ghost">📁 Abrir imagen/archivo</button>
    </div>
    <input id="fileinput" type="file" accept="image/*,.dpair,.json,text/plain" style="display:none">
    <div id="scanarea"></div>
    <details><summary>…o pegar el código a mano</summary>
      <textarea id="qr" rows="3" placeholder='{"v":2,"iss":"…","proxy":"…","token":"…","sn":"…"}'></textarea>
      <div><button id="connect" class="btn ghost">Conectar con el código pegado</button></div>
    </details>
    <div id="vmsg"></div>
  </div>`)

  const msg = () => document.getElementById('vmsg')
  async function doConnect (qr, skip) {
    if (!qr || !qr.iss || !qr.token) { msg().innerHTML = '<div class="banner bad">No reconocí un código de emparejamiento válido. Volvé a generar el QR con <code>dotrino-vault pair</code>.</div>'; return }
    if (!qr.sn || (qr.v && qr.v < 2)) { msg().innerHTML = '<div class="banner bad">Este código es de una <strong>versión vieja</strong> del vault. Actualizá a la última y reiniciá el servicio (<code>systemctl --user restart dotrino-vault</code>), confirmá con <code>dotrino-vault status</code>, y generá un código nuevo con <code>dotrino-vault pair</code>.</div>'; return }
    // Elegir CON QUÉ PERFIL conectar esta bóveda (o uno nuevo) ANTES de emparejar.
    if (!skip) {
      const profiles = await id.listProfiles().catch(() => [])
      const cur = profiles.find((p) => p.current) || profiles[0]
      msg().innerHTML = `<div class="sas-box" style="text-align:left">
        <p><strong>¿Con qué perfil quieres conectar esta bóveda?</strong></p>
        <p class="muted">Cada perfil tiene su propia bóveda. Elige uno existente o conecta uno nuevo.</p>
        <div class="pf-pick" style="display:flex;flex-direction:column;gap:8px;margin:10px 0"></div>
        <button class="btn ghost" id="pick-new">+ Conectar un perfil nuevo</button>
      </div>`
      const host = msg().querySelector('.pf-pick')
      host.innerHTML = profiles.map((p) => `<button class="btn ${p.current ? '' : 'ghost'} pick-prof" data-id="${esc(p.id)}">${esc(p.name || 'Perfil sin nombre')}${p.current ? ' · activo' : ''}</button>`).join('')
      host.querySelectorAll('.pick-prof').forEach((b) => { b.onclick = async () => {
        const pid = b.dataset.id
        if (cur && pid === cur.id) { doConnect(qr, true) } // ya activo → emparejar directo
        else { sessionStorage.setItem('cc-pair-intent', JSON.stringify(qr)); await id.switchProfile(pid); location.reload() }
      } })
      msg().querySelector('#pick-new').onclick = async () => { sessionStorage.setItem('cc-pair-intent', JSON.stringify(qr)); await id.createProfile(''); location.reload() }
      return
    }
    msg().innerHTML = '<div class="banner">Conectando…</div>'
    const off = id.onVault((e) => {
      if (e.phase === 'challenge') {
        msg().innerHTML = `<div class="sas-box">
          <p>Tu <strong>código de emparejamiento</strong>:</p>
          <div class="sas">${esc(e.code)}</div>
          <p class="muted">Ingresalo en tu PC para conectar este dispositivo (el vault no lo conoce hasta que vos se lo das):</p>
          <p><code>dotrino-vault approve ${esc(e.code)}</code></p>
          <p class="muted">Esperando que lo apruebes en el PC…</p></div>`
      }
    })
    try {
      await id.enrollDevice(qr); off()
      msg().innerHTML = '<div class="banner ok">✓ ¡Conectado! Este dispositivo ahora usa tu bóveda.</div>'
      setTimeout(() => vaultMode(), 1600)
    } catch (e) { off(); msg().innerHTML = `<div class="banner bad">No se pudo conectar: ${esc(e.message)}</div>` }
  }

  document.getElementById('connect').onclick = () => {
    try { doConnect(JSON.parse(document.getElementById('qr').value.trim())) }
    catch { msg().innerHTML = '<div class="banner bad">Ese código pegado no es válido.</div>' }
  }
  document.getElementById('scan').onclick = async () => {
    const text = await scanWithCamera(document.getElementById('scanarea'))
    if (text) doConnect(extractPayload(text))
  }
  document.getElementById('openfile').onclick = () => document.getElementById('fileinput').click()
  document.getElementById('fileinput').onchange = async (ev) => {
    const f = ev.target.files?.[0]; if (!f) return
    let text
    if (/^image\//.test(f.type)) { text = await decodeQrFromImage(f); if (!text) { msg().innerHTML = '<div class="banner bad">No encontré un QR en esa imagen.</div>'; return } }
    else { text = await f.text() }
    doConnect(extractPayload(text))
  }

  // Retomar tras elegir perfil (intent) → emparejar directo. Si el QR vino en la URL, mostrar el selector.
  if (intentQr) doConnect(intentQr, true)
  else if (prefillQr) doConnect(prefillQr)
}

/* ── #myvault: ESTE dispositivo actúa como su propia bóveda (modo self) ──
   El daemon device-vault vive dentro del iframe de identidad (no requiere el
   binario del PC). Aquí lo activas, generas códigos de emparejamiento para
   enlazar agentes (ia, terminal), apruebas con SAS y listas/revocas máquinas —
   todo por RPC al iframe vía @dotrino/identity. */
let _svPresenceTimer = null
const svEl = (h) => { const tp = document.createElement('template'); tp.innerHTML = h.trim(); return tp.content.firstElementChild }

async function selfVaultMode () {
  injectVaultStyles()
  // ?back= la app que nos llamó (sólo http/https, para evitar open-redirect)
  let backHref = null, backHost = null
  try {
    const b = new URLSearchParams(location.search).get('back')
    if (b) { const u = new URL(b); if (u.protocol === 'http:' || u.protocol === 'https:') { backHref = u.origin + u.pathname; backHost = u.hostname } }
  } catch {}
  const backBtn = backHost ? `<p style="margin-top:14px"><button class="btn ghost" id="svBack" data-testid="sv-back">← Volver a ${esc(backHost)}</button></p>` : ''

  let id
  try { id = await Identity.connect() } catch {}
  if (!id?.me?.publickey) {
    vaultShell('Mi bóveda', `<div class="vault-wrap"><p class="status">Necesitas una identidad primero. Créala en la sección <a href="/" style="color:#00658c">Tu perfil</a>.</p>${backBtn}</div>`, 'Mi bóveda')
    document.getElementById('svBack')?.addEventListener('click', () => { location.href = backHref })
    return
  }

  vaultShell('Mi bóveda', `<div class="vault-wrap"><div id="sv-root"><span class="status">Cargando…</span></div>${backBtn}</div>`, 'Mi bóveda')
  document.getElementById('svBack')?.addEventListener('click', () => { location.href = backHref })
  const root = document.getElementById('sv-root')

  let pairBox, machinesBox
  // Eventos del daemon del iframe: { pending? running? error? }
  id.onSelfVault((p) => {
    if (!p) return
    if (Array.isArray(p.pending)) renderPending(p.pending)
    if (typeof p.running === 'boolean') {
      const badge = root.querySelector('#svStatus')
      if (badge) badge.textContent = p.running ? 'Bóveda activa en este dispositivo' : 'Bóveda activa (daemon inactivo en esta pestaña — abrila como visible)'
    }
  })

  async function render () {
    if (_svPresenceTimer) { clearInterval(_svPresenceTimer); _svPresenceTimer = null }
    let status
    try { status = await id.selfVaultStatus() } catch { status = { enabled: false, running: false } }

    if (!status.enabled) {
      root.innerHTML = `<p class="status">Activa este dispositivo como tu bóveda para enlazar agentes (ia, terminal) que firmen en tu nombre sin exponer tu llave maestra. La llave nunca sale de este navegador.</p>
        <div class="sv-toggle-row"><span class="status">Estado: desactivado</span></div>
        <button class="btn" id="svEnable" data-testid="sv-enable">Activar como bóveda</button>`
      document.getElementById('svEnable').addEventListener('click', async () => { await id.setSelfVault(true); render() })
      return
    }

    root.innerHTML = `<span class="sv-status" id="svStatus">${status.running ? 'Bóveda activa en este dispositivo' : 'Bóveda activa (daemon inactivo en esta pestaña — abrila como visible)'}</span>
      <button class="btn ghost" id="svDisable" data-testid="sv-disable" style="margin-left:8px">Desactivar</button>
      <div class="sv-block" id="svPair"></div>
      <div class="sv-block" id="svMachines"><span class="status">Aún no hay máquinas enlazadas.</span></div>`
    document.getElementById('svDisable').addEventListener('click', async () => { await id.setSelfVault(false); render() })

    pairBox = document.getElementById('svPair')
    machinesBox = document.getElementById('svMachines')

    function renderPairIdle () {
      pairBox.innerHTML = `<div class="sv-setup"><button class="btn" id="svStartPair" data-testid="sv-start-pair">Generar código de emparejamiento</button></div>`
      document.getElementById('svStartPair').addEventListener('click', startPairing)
    }
    async function startPairing () {
      let qr
      try { ({ qr } = await id.selfVaultPairing()) } catch { return }
      const json = JSON.stringify(qr)
      const code = b64urlEncode(json)
      pairBox.innerHTML = `<div class="sv-setup">
        <p class="status">Pega este código en el agente (ia/terminal) que quieres enlazar:</p>
        <div class="sv-qr-wrap" title="QR">${qrSvg(json)}</div>
        <div class="sv-qr-code"><pre><code>${esc(code)}</code></pre></div>
        <button class="btn ghost" id="svCopy">Copiar código</button>
        <span class="status" id="svCopyMsg"></span>
        <p class="status">El agente pedirá aprobación con un código que TIPEAS aquí.</p>
        <p class="status">⏳ Esperando a que pida acceso…</p>
        <button class="btn ghost" id="svCancel">Cancelar</button>
      </div>`
      document.getElementById('svCopy').addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(code); document.getElementById('svCopyMsg').textContent = 'Copiado' } catch {}
      })
      document.getElementById('svCancel').addEventListener('click', renderPairIdle)
    }

    function renderPending (list) {
      if (!pairBox) return
      if (!list || !list.length) { if (pairBox.querySelector('.sv-pending')) renderPairIdle(); return }
      const rows = list.map((x) => `
        <div class="sv-pending" data-device="${esc(x.deviceId)}">
          <p class="status">La máquina ${esc(x.deviceId)} pide acceso. Tipea el código que muestra:</p>
          <div class="sv-pair-actions">
            <input class="sv-code-input" data-code="${esc(x.deviceId)}" type="text" inputmode="numeric" autocomplete="off" maxlength="8" placeholder="código" aria-label="código" data-testid="sv-code" />
            <button class="btn" data-approve="${esc(x.deviceId)}" data-testid="sv-approve">Aprobar</button>
            <button class="btn ghost" data-reject="${esc(x.deviceId)}">Rechazar</button>
          </div>
        </div>`).join('')
      pairBox.innerHTML = `<div class="sv-setup">${rows}</div>`
      const approveWith = async (b) => {
        const dev = b.dataset.approve
        const input = pairBox.querySelector(`input[data-code="${CSS.escape(dev)}"]`)
        const code = (input?.value || '').trim()
        if (!code) { input?.focus(); return }
        b.disabled = true
        try { await id.selfVaultApprove(dev, code); refreshMachines() } catch { b.disabled = false }
      }
      pairBox.querySelectorAll('[data-approve]').forEach((b) => {
        b.addEventListener('click', () => approveWith(b))
        const input = pairBox.querySelector(`input[data-code="${CSS.escape(b.dataset.approve)}"]`)
        input?.addEventListener('keydown', (e) => { if (e.key === 'Enter') approveWith(b) })
      })
      pairBox.querySelectorAll('[data-reject]').forEach((b) => b.addEventListener('click', () => id.selfVaultReject(b.dataset.reject)))
    }

    try { renderPending(await id.selfVaultPending()) } catch {}
    renderPairIdle()

    async function updatePresence (subs) {
      if (!subs.length) return
      let online = new Set()
      try { const r = await id.selfVaultProbe(subs); online = new Set(r.online || []) } catch {}
      for (const row of machinesBox.querySelectorAll('.sv-machine-row')) {
        const dot = row.querySelector('.sv-mdot'); if (!dot) continue
        const on = online.has(row.dataset.sub)
        dot.className = 'sv-mdot ' + (on ? 'on' : 'off')
        dot.title = on ? 'en línea' : 'desconectado'
      }
    }
    async function refreshMachines () {
      try {
        const list = await id.selfVaultMachines()
        if (!list.length) {
          machinesBox.innerHTML = `<span class="status">Aún no hay máquinas enlazadas.</span>`
          return
        }
        machinesBox.innerHTML = `<b>Máquinas enlazadas</b><div class="sv-machine-list"></div>`
        const holder = machinesBox.querySelector('.sv-machine-list')
        for (const d of list) {
          const name = d.label ? `${d.label} · ${d.deviceId}` : d.deviceId
          holder.appendChild(svEl(`<div class="sv-machine-row" data-sub="${esc(d.sub)}">
            <span class="sv-machine-name"><span class="sv-mdot" title="comprobando…"></span>🖥 ${esc(name)}</span>
            <button class="btn ghost" data-revoke="${esc(d.nonce)}">Revocar</button>
          </div>`))
        }
        machinesBox.querySelectorAll('[data-revoke]').forEach((b) => b.addEventListener('click', async () => { await id.selfVaultRevoke(b.dataset.revoke); refreshMachines() }))
        updatePresence(list.map((d) => d.sub))
      } catch { machinesBox.innerHTML = `<span class="status">Aún no hay máquinas enlazadas.</span>` }
    }
    refreshMachines()
    _svPresenceTimer = setInterval(() => {
      const subs = [...machinesBox.querySelectorAll('.sv-machine-row')].map((r) => r.dataset.sub)
      if (subs.length) updatePresence(subs)
    }, 30000)
  }

  render()
}

async function main() {
  const data = parseHash()

  // SIEMPRE limpiar el hash de la URL: `#vault=` lleva el TOKEN de emparejamiento
  // (un secreto de 5 min) y no debe quedar en la barra ni en el historial; los
  // otros modos (#v=, #pubkey) ya se capturaron en `data`. replaceState no
  // dispara 'hashchange', así que no recarga. El reingreso al emparejamiento
  // tras cambiar de perfil NO depende del hash (usa sessionStorage 'cc-pair-intent').
  let pendingPair = false
  try { pendingPair = !!sessionStorage.getItem('cc-pair-intent') } catch (_) {}
  if (location.hash) { try { history.replaceState(null, '', location.pathname + location.search) } catch (_) {} }

  if (data.mode === 'vault' || pendingPair) return vaultMode(data.qr)
  if (data.mode === 'selfvault') return selfVaultMode()

  // ── VALIDAR: firma del contenido + reputación del remitente, en un paso ──
  if (data.mode === 'validate') {
    const p = data.payload || {}
    const signed = { op: p.op || 'app-request', text: p.text, ts: p.ts }
    const ok = await verifySig(p.pubkey, signed, p.signature)
    const banner = ok
      ? `<div class="banner ok">✓ Firma válida${p.nickname ? ` — firmado por <strong>${esc(p.nickname)}</strong>` : ''}</div>`
      : `<div class="banner bad">✗ Firma inválida o no verificable</div>`
    const content = p.text ? `<div class="content">${esc(p.text)}</div>` : ''
    mount.innerHTML = `<div class="validate-wrap">${banner}${content}<div id="prof"></div></div>`
    if (p.pubkey) {
      const el = makeProfile({ pubkey: p.pubkey, name: p.nickname, mode: 'edit', modal: false })
      document.getElementById('prof').appendChild(el)
      try { const { provider } = await connectProvider(); el.provider = provider } catch { /* reputación opcional */ }
    }
    return
  }

  if (data.mode === 'invalid') {
    showState('Link inválido', '<p>Este enlace no es válido.</p>')
    return
  }

  // ── RATE (#pubkey) o SELF (sin hash): perfil modal, requiere identidad ──
  let id, provider
  try { ({ id, provider } = await connectProvider()) } catch {
    showState('No se pudo conectar tu identidad', '<p>Esto requiere tu identidad de Dotrino. Recarga e inténtalo de nuevo.</p>')
    return
  }

  let pubkey, name, since, mode
  if (data.mode === 'rate') {
    pubkey = data.pubkey; name = data.name; since = data.since; mode = 'edit'
  } else {
    // Siempre hay identidad (el vault crea un perfil al cargar). Usamos el PERFIL ACTIVO.
    const cur = id.currentProfile ? await id.currentProfile().catch(() => null) : null
    pubkey = cur?.pubkey || (id && id.me && id.me.publickey); name = cur?.name || (id && id.me && id.me.nickname); mode = 'self'
  }

  // SELF (tu perfil): topbar + el componente inline, que YA trae el switcher de
  // perfiles (cambiar) y —AQUÍ, con `manage`— crear perfil. Debajo, la sección de
  // PIN, exclusiva de ESTA página (no aparece en el popup de las otras apps).
  if (mode === 'self') {
    injectVaultStyles()
    vaultShell('Tu perfil', '<div class="vault-wrap"><div id="self-prof"></div><div id="pin-section"></div><div class="sv-link-row"><p class="status">Convierte este dispositivo en tu bóveda para enlazar agentes (ia, terminal) que firmen en tu nombre.</p><a href="#myvault" data-testid="goto-myvault">Mi bóveda →</a></div></div>', 'Perfiles')
    const el = makeProfile({ pubkey, name, since, mode, modal: false, manage: true })
    el.provider = provider
    document.getElementById('self-prof')?.appendChild(el)
    renderPinSection(document.getElementById('pin-section'))
    return
  }

  const el = makeProfile({ pubkey, name, since, mode, modal: true })
  el.provider = provider
  mount.innerHTML = ''
  mount.appendChild(el)
}

window.addEventListener('hashchange', () => window.location.reload())
main()
