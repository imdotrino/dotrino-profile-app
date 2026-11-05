// Tipos de los subpaths de @dotrino/identity que esta app importa y que el paquete
// publica SIN declaraciones (identity 0.117.2: solo `.` lleva `types`). Describen lo que
// hace el código de `node_modules/@dotrino/identity/vault/*.js`; si el pilar publica sus
// propios tipos, este archivo se borra.

declare module '@dotrino/identity/capabilities' {
  export { makeDeviceKey, signWithDevice } from '@dotrino/identity'
  /** Comprueba que `signature` (base64) sobre `data` la hizo la privada de `publickey` (JWK string). */
  export function verifyDeviceSig (args: { publickey: string; data: unknown; signature: string }): Promise<boolean>
  export function avatarDataUri (seed: string, opts?: Record<string, unknown>): string
}

declare module '@dotrino/identity/keyid' {
  /** La huella legible de una llave (`AB12-CD34`). */
  export function keyLabel (publicJwkStr: string): Promise<string>
  export function pubkeyId (publicJwkStr: string): Promise<string>
}

declare module '@dotrino/identity/session' {
  export { verifySession, cleanSessionScopes } from '@dotrino/identity'
}

declare module '@dotrino/identity/session-flow' {
  import type { SessionPaper, SessionScope } from '@dotrino/identity'

  /** Lo que viaja en el QR de «entrar en otro navegador». */
  export interface SessionInvite {
    v: 1
    t: 'session'
    sid: string
    /** Pubkey (JWK string) de la llave de sesión del que entra. */
    s: string
    encPub?: string
    origin: string
    scopes: SessionScope[]
    proxy?: string
  }

  /** Lo mínimo que estas funciones le piden al transporte (un WebSocketProxyClient). */
  export interface SessionTransport {
    url?: string
    on (event: 'message', handler: (from: string, payload: unknown, meta?: { sealed?: boolean }) => void): () => void
    sendByPubkey (pubkey: string, payload: unknown): unknown
    sendSealed? (pubkeys: string[], payload: unknown, opts?: { peerEncPub?: string }): Promise<unknown>
  }

  export function sessionCode (sid: string): string
  export function parseInvite (raw: unknown): SessionInvite | null
  export function openSession (args: {
    transport: SessionTransport
    sessionPubkey: string
    encPub?: string
    origin: string
    scopes?: string[]
    onInvite?: (x: { invite: SessionInvite; code: string; qr: string }) => void
    timeoutMs?: number
    sid?: string
  }): Promise<{ paper: SessionPaper; chain: unknown[]; profileId: string; sid: string; scopes: SessionScope[]; exp: number }>
  export function grantSession (args: {
    transport: SessionTransport
    invite: SessionInvite
    by: string
    sign: (body: unknown) => Promise<unknown>
    chain: unknown[]
    scopes?: string[]
    ttlMs?: number
    now?: number
  }): Promise<SessionPaper>
  export function denySession (args: { transport: SessionTransport; invite: SessionInvite }): Promise<void>
  export function closeSession (args: { transport: SessionTransport; sessionPubkey: string; encPub?: string; sid: string }): Promise<void>
}
