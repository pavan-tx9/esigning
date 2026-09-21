# esign signing UI

Bun, Vite, React 19, TypeScript strict, TanStack Query, Tailwind v4 (CSS-first), Base UI, Zod,
pdf.js, Biome. `@/` aliases `src/`.

```
bun install
bun run dev        # :5273, proxying /v1 to the API on :8000
bun run typecheck  # tsc
bun run check      # biome: lint + format + import sort
bun run check:fix
bun run test       # vitest + jsdom + testing-library, msw for the API
bun run e2e        # playwright (chromium), starts the dev server itself
```

## Conventions

- **`fetch` lives in `src/lib/api.ts` and nowhere else.** Biome's `noRestrictedGlobals` fails the
  lint anywhere else, and the same rule bans `localStorage` and `sessionStorage`: the signing token
  is held in memory for the life of the page, never in a URL and never in browser storage.
- **Every response is parsed with Zod** at that seam before a component sees it. A non-2xx becomes
  an `ApiError` carrying the server's stable `code`; a shape mismatch becomes `ApiValidationError`.
- **All server state is TanStack Query.** No component hand-rolls `useState` + `useEffect` + fetch.
- Tailwind is configured in `src/styles.css` under `@theme`. There is no `tailwind.config.js`.
- `src/` belongs to the frontend module. This scaffold is the floor it builds on: `App.tsx` is a
  placeholder for the six-state flow in SPEC section 11.

Port 5273, not the usual 5173, and `strictPort` is on: a signing UI that silently attaches to
another project's dev server is worse than one that refuses to start.
