// Métodos de `Identity` que el código de @dotrino/identity 0.117.2 tiene (src/index.js) y
// que su `index.d.ts` no declara. Se suman aquí por fusión de declaraciones; cuando el
// pilar los declare, este archivo se borra.
import '@dotrino/identity'

declare module '@dotrino/identity' {
  interface Identity {
    /** Estado del candado del perfil activo. */
    profileLockStatus (): Promise<{ protected: boolean; locked?: boolean }>
    /** Protege el perfil activo con PIN, solo en este dispositivo. */
    setProfilePassword (password: string): Promise<unknown>
    removeProfilePassword (): Promise<unknown>
    /** La cadena de selladores, para mandarla junto a una firma. */
    sealerChain (): Promise<unknown[]>
    /** La firma real admite un objeto (el QR ya leído) y `join` (`'new'` | `'current'`). */
    enrollDevice (qr: object, opts?: { label?: string; join?: 'new' | 'current' }): Promise<{ ok: boolean; deviceId: string; master: string; exp: number; scope: string[] }>
    createProfile (name: string, opts?: { forVault?: boolean }): Promise<unknown>
    loginWithPassword (args: { address: string; password: string; remember?: boolean; label?: string; proxyUrl?: string | null }): Promise<unknown>
    /** Mezcla en tu perfil (nickname, avatar, campos y sus banderas `<campo>Visible`). */
    updateMe (patch: Record<string, unknown>): Promise<unknown>
  }
}
