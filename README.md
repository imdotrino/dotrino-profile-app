# Perfil — profile.dotrino.com

Tu identidad en Dotrino, en una página. Administra tus **perfiles**, tu nombre,
tu foto y tus datos; protégelos con un PIN en este dispositivo; conecta tu
bóveda, revisa tus dispositivos y califica a las personas con las que
interactúas.

Es la **única** app donde se crea y se cambia de perfil: el resto del ecosistema
usa el perfil activo y, al cambiarlo, recarga.

## Cómo encaja

- La tarjeta de perfil es el componente compartido `<dotrino-profile>`
  (`@dotrino/profile`), igual que en cualquier otra app (§6.1). Aquí va en modo
  administrable.
- La identidad y las llaves son de `@dotrino/identity` (bóveda
  `id.dotrino.com`); las calificaciones, de `@dotrino/reputation`.

## Stack

Vite (sin framework). Pilares: `@dotrino/identity`, `@dotrino/profile`,
`@dotrino/reputation`, `@dotrino/topbar`.

## Desarrollo

```sh
npm install
npm run dev
npm run build      # → dist/
npm run type-check
```

## Deploy

GitHub Actions construye `dist/` y lo publica en Pages bajo
**`https://profile.dotrino.com/`** (`.github/workflows/deploy.yml`).

## Privacidad

La clave privada no sale del dispositivo, y el PIN se verifica localmente. Esta
página es **interna**: va con `noindex` y su `robots.txt` en `Disallow: /`, para
que ningún buscador indexe nada de nadie.

## Licencia

MIT — © Dotrino
