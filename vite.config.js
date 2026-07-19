import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'

// App interna chica (sin framework): el perfil es un Web Component.
// Usa PATHS para las vistas (/myvault, /vault) además de la home (/). GitHub Pages
// no tiene rewrites, pero SÍ sirve un archivo `<vista>.html` en la URL `/<vista>`
// (extensionless, con HTTP 200 y sin redirección). Así que emitimos una copia del
// index.html construido (con sus assets hasheados) por cada vista: `myvault.html`,
// `vault.html`. La SPA enruta por `location.pathname`. Con `base` relativo (Vite por
// defecto '/', aquí NO lo cambiamos: los assets son relativos al index) los assets
// resuelven bien desde `/myvault` (mismo directorio `/`) y desde el mirror github.io.
// `404.html` queda como red de seguridad para cualquier otra ruta sin archivo.
function spaRoutes () {
  const views = ['404.html', 'myvault.html', 'vault.html']
  return {
    name: 'spa-routes',
    closeBundle () {
      const idx = path.resolve('dist', 'index.html')
      if (!fs.existsSync(idx)) return
      for (const name of views) fs.copyFileSync(idx, path.resolve('dist', name))
    }
  }
}

export default defineConfig({
  base: './',
  build: { target: 'es2020' },
  plugins: [spaRoutes()],
})
