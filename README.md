# @mostajs/auth-lite

> Minimal email/password + session auth for **Next.js (App Router)** on top of [`@mostajs/orm`](https://www.npmjs.com/package/@mostajs/orm).
> **No native addon** (no bcrypt/argon2) → it boots in **Bolt.new / StackBlitz / WebContainers / the edge**, on the first try.

[![npm](https://img.shields.io/npm/v/@mostajs/auth-lite)](https://www.npmjs.com/package/@mostajs/auth-lite)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](./LICENSE)

`auth-lite` is the **readable, dependency-free** auth brick: salted iterated SHA-256
password hashing (Node core `crypto`), a ready-made `Session` schema, login/signup/logout
Route Handlers, and a `getCurrentUser()` for Server Components. It was extracted from the
`mostajs-saas-starter` and hardened until it actually boots inside the StackBlitz
WebContainer — the lessons learned are baked into its API (see [Why "lite"](#why-lite--webcontainer-safe-by-design)).

> **Need OAuth, MFA, WebAuthn, magic links, Argon2id, refresh tokens?** Use the full
> [`@mostajs/auth`](https://www.npmjs.com/package/@mostajs/auth) instead. `auth-lite` and
> `@mostajs/auth` are alternatives — pick one (see [comparison](#auth-lite-vs-mostajsauth)).

---

## Install

```bash
npm i @mostajs/auth-lite @mostajs/orm next
```

Peer requirements: `@mostajs/orm >= 2.5.2`, `next >= 14`.
To boot in a browser / WebContainer, use one of the ORM's WASM dialects (`sqljs` or `pglite`)
so there is **zero native binary** in the dependency tree.

---

## Quickstart (5 steps)

### 1 · Schemas — your `User` + the bundled `Session`

Your `User` entity must have at least `email` (unique), `passwordHash`, and `name`.

```ts
// lib/orm/schemas.ts
import type { EntitySchema } from '@mostajs/orm';
export { SessionSchema } from '@mostajs/auth-lite';

export const UserSchema: EntitySchema = {
  name: 'User',
  collection: 'users',
  fields: {
    email:        { type: 'string', required: true, unique: true, lowercase: true, trim: true },
    name:         { type: 'string', required: true, trim: true },
    passwordHash: { type: 'string', required: true },
  },
  indexes: [{ fields: ['email'], unique: true }],
  timestamps: true,
};
```

### 2 · Repos — expose `getRepos()`

```ts
// lib/orm/index.ts
import { BaseRepository } from '@mostajs/orm';
import { getDialect } from '@mostajs/orm';
import { SessionSchema } from '@mostajs/auth-lite';
import { UserSchema } from './schemas';

export type User = { id: string; email: string; name: string; passwordHash: string };

export async function getRepos() {
  const dialect = await getDialect(
    { dialect: 'sqljs', uri: ':memory:' },   // WASM → boots in Bolt/StackBlitz
    [UserSchema, SessionSchema],
  );
  return {
    users:    new BaseRepository<User>(UserSchema, dialect),
    sessions: new BaseRepository(SessionSchema, dialect),
  };
}
```

### 3 · Route Handlers — login / signup / logout

```ts
// app/api/auth/login/route.ts
import { createAuthHandlers } from '@mostajs/auth-lite';
import { getRepos } from '@/lib/orm';
export const POST = createAuthHandlers({ getRepos }).login;
```

```ts
// app/api/auth/signup/route.ts
import { createAuthHandlers } from '@mostajs/auth-lite';
import { getRepos } from '@/lib/orm';
export const POST = createAuthHandlers({ getRepos }).signup;
```

```ts
// app/api/auth/logout/route.ts
import { createAuthHandlers } from '@mostajs/auth-lite';
import { getRepos } from '@/lib/orm';
export const POST = createAuthHandlers({ getRepos }).logout;
```

### 4 · Read the session in Server Components

```ts
// lib/auth.ts
import { createGetCurrentUser } from '@mostajs/auth-lite';
import { getRepos, type User } from '@/lib/orm';
export const getCurrentUser = createGetCurrentUser<User>({ getRepos });
```

### 5 · Forms post to the handlers (works without client JS)

```tsx
// app/login/page.tsx
export default function LoginPage() {
  return (
    <form action="/api/auth/login" method="post">
      <input name="email" type="email" required />
      <input name="password" type="password" required />
      <button type="submit">Log in</button>
    </form>
  );
}
```

Guard each protected page:

```tsx
// app/dashboard/page.tsx
import { redirect } from 'next/navigation';
import { getCurrentUser } from '@/lib/auth';

export const dynamic = 'force-dynamic';

export default async function Dashboard() {
  const user = await getCurrentUser();
  if (!user) redirect('/login');         // ← per page, not only in the layout
  return <p>Welcome, {user.name}</p>;
}
```

---

## API

| Export | Signature | Purpose |
|---|---|---|
| `hashPassword` | `(password: string) => string` | Salted, 10 000× iterated SHA-256 → `"salt:hashHex"`. No native addon. |
| `verifyPassword` | `(password: string, stored: string) => boolean` | Constant-time check (`timingSafeEqual`). |
| `SessionSchema` | `EntitySchema` | `Session` entity (`token` unique, `expiresAt`, `user` → `User` M-1 cascade). Register it alongside `User`. |
| `createAuthHandlers` | `(config) => { login, signup, logout }` | Each is `(req: NextRequest) => Promise<NextResponse>`; export as `POST`. |
| `createGetCurrentUser` | `<TUser>(config) => () => Promise<TUser \| null>` | Resolve the logged-in user from the cookie (read before any DB call). |

### `AuthLiteConfig`

```ts
interface AuthLiteConfig {
  getRepos: () => Promise<{ users: AuthRepo; sessions: AuthRepo }>; // required
  cookieName?: string;        // default "session"
  ttlDays?: number;           // default 7
  afterAuth?: string;         // default "/dashboard"
  afterLogout?: string;       // default "/"
  loginErrorPath?: string;    // default "/login?error=invalid"
  signupErrorPath?: (kind: 'invalid' | 'exists') => string; // default "/signup?error=<kind>"
}
```

`AuthRepo` is the minimal subset this module needs (`findOne`, `create`, `delete`,
`findByIdWithRelations`) — fully satisfied by `@mostajs/orm`'s `BaseRepository`.

---

## Why "lite" — WebContainer-safe by design

Tested for real in StackBlitz; the failures it hit are now prevented by the API itself:

- **Cookies via Route Handlers, not `cookies()`.** Some runtimes (StackBlitz WebContainer)
  lose Next's request async-context (AsyncLocalStorage) across an `await` on the DB, which
  makes a later `cookies()` throw *"called outside a request scope"*. `createAuthHandlers`
  sets the cookie on the **`NextResponse`** object (`res.cookies.set`) — that works everywhere.
- **Read the cookie before the DB.** `getCurrentUser` reads the cookie while the request
  context is still intact, then resolves the session.
- **No native binary.** SHA-256 from Node core `crypto` — no bcrypt/argon2 to compile. For a
  classic production server you can swap in argon2/scrypt (the `hashPassword`/`verifyPassword`
  API is unchanged) or move to `@mostajs/auth`.
- **Guard per page.** Always `if (!user) redirect('/login')` in each protected page — a layout
  guard alone is not enough (layout and page run in parallel → `null.id` crash).

---

## `auth-lite` vs `@mostajs/auth`

| | `@mostajs/auth-lite` | `@mostajs/auth` |
|---|---|---|
| Password hash | SHA-256 iterated (core crypto) | Argon2id |
| Methods | email/password + sessions | email/password, OAuth/OIDC, magic link, MFA TOTP, WebAuthn/Passkeys |
| Stack | `@mostajs/orm` + Next Route Handlers | NextAuth v5 + `@mostajs/rbac` |
| Native deps | **none** (WebContainer/edge ready) | argon2 etc. (server) |
| Footprint | one file, readable | ~30 sub-paths, full-featured |
| Best for | starters, MVPs, Bolt/StackBlitz demos | production apps needing rich auth |

They are **alternatives** — depend on one, not both.

---

## License

AGPL-3.0-or-later. A commercial license is available for proprietary/closed-source use —
see [`LICENSE`](./LICENSE).

**Author**: Dr Hamid MADANI <drmdh@msn.com>
