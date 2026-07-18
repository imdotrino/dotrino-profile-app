import { defineConfig } from 'vite'
import fs from 'node:fs'
import path from 'node:path'

// App interna chica (sin framework): el perfil es un Web Component.
// Usa PATHS para las vistas (/myvault, /vault) además de la home (/). GitHub Pages
// no tiene rewrites: sirve `404.html` para cualquier ruta sin archivo. Copiamos el
// index.html construido (con sus assets hasheados) a 404.html para que ESAS rutas
// carguen la SPA y ésta enrute por location.pathname. En dev/preview Vite ya hace
// fallback a index.html, así que esto sólo hace falta en producción (Pages).
function spa404 () {
  return {
    name: 'spa-404',
    closeBundle () {
      const idx = path.resolve('dist', 'index.html')
      if (fs.existsSync(idx)) fs.copyFileSync(idx, path.resolve('dist', '404.html'))
    }
  }
}

export default defineConfig({
  build: { target: 'es2020' },
  plugins: [spa404()],
})
