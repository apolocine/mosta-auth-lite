/**
 * @mostajs/auth-lite/next — Next.js (App Router) adapter.
 *
 * Route Handlers (login/signup/logout) + `getCurrentUser`. Imports `next/server`
 * and `next/headers` **statically** on purpose:
 *   - the cookie is set on the `NextResponse` object (no `cookies()` write),
 *   - redirects use a **relative** `Location` → resolved by the browser against
 *     the public request URL, so it works in WebContainers (StackBlitz/Bolt,
 *     which don't forward the public host) and behind a reverse proxy,
 *   - `getCurrentUser` calls `cookies()` as the **first `await`** (no dynamic
 *     `import` before it) → the request AsyncLocalStorage scope stays intact in
 *     constrained runtimes (a preceding `await import(...)` loses it).
 *
 * The framework-agnostic core (hashing, `SessionSchema`, types) is in the root
 * entry `@mostajs/auth-lite`.
 *
 * @author Dr Hamid MADANI <drmdh@msn.com>
 */
import { type NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { randomBytes } from 'crypto';
import { hashPassword, verifyPassword, type AuthRepo, type AuthLiteConfig } from './index.js';

export type { AuthRepo, AuthLiteConfig };

/**
 * 303 response with a **relative** `Location` (e.g. `/dashboard`). The browser
 * resolves it against the current request's public URL → works in WebContainer
 * / reverse-proxy / localhost without the server knowing its own host.
 */
function see(location: string): NextResponse {
  return new NextResponse(null, { status: 303, headers: { Location: location } });
}

// ---------------------------------------------------------------------------
// Route Handlers — login / signup / logout (cookie set on the response)
// ---------------------------------------------------------------------------

export function createAuthHandlers(config: AuthLiteConfig) {
  const cookie = config.cookieName ?? 'session';
  const ttlMs = (config.ttlDays ?? 7) * 86400000;
  const afterAuth = config.afterAuth ?? '/dashboard';
  const afterLogout = config.afterLogout ?? '/';
  const loginError = config.loginErrorPath ?? '/login?error=invalid';
  const signupError = config.signupErrorPath ?? ((k: 'invalid' | 'exists') => `/signup?error=${k}`);
  const crossSite = config.crossSiteCookie ?? false;

  /** La requête arrive-t-elle en https (proxy forwarde `x-forwarded-proto`, ou URL https) ? */
  function isHttps(req: NextRequest): boolean {
    if (req.headers.get('x-forwarded-proto') === 'https') return true;
    try { return new URL(req.url).protocol === 'https:'; } catch { return false; }
  }

  /**
   * Attributs du cookie de session. `crossSiteCookie` + https → `sameSite:'none'`
   * + `secure` (cookie renvoyé en iframe cross-site, ex. CodeSandbox). Sinon
   * `sameSite:'lax'` (et pas de `secure`, pour que localhost http garde la session).
   */
  function cookieOpts(req: NextRequest, expires: Date) {
    if (crossSite && isHttps(req)) {
      return { httpOnly: true, sameSite: 'none' as const, secure: true, path: '/', expires };
    }
    return { httpOnly: true, sameSite: 'lax' as const, path: '/', expires };
  }

  async function openSession(req: NextRequest, sessions: AuthRepo, userId: string): Promise<NextResponse> {
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + ttlMs);
    await sessions.create({ token, user: userId, expiresAt });
    const res = see(afterAuth);
    res.cookies.set(cookie, token, cookieOpts(req, expiresAt));
    return res;
  }

  /** POST handler — verify credentials, start a session. */
  async function login(req: NextRequest) {
    const form = await req.formData();
    const email = String(form.get('email') ?? '').toLowerCase().trim();
    const password = String(form.get('password') ?? '');
    const { users, sessions } = await config.getRepos();
    const user = await users.findOne({ email });
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return see(loginError);
    }
    return openSession(req, sessions, user.id);
  }

  /** POST handler — create the account, start a session. */
  async function signup(req: NextRequest) {
    const form = await req.formData();
    const email = String(form.get('email') ?? '').toLowerCase().trim();
    const name = String(form.get('name') ?? '').trim();
    const password = String(form.get('password') ?? '');
    if (!email || !name || password.length < 6) {
      return see(signupError('invalid'));
    }
    const { users, sessions } = await config.getRepos();
    if (await users.findOne({ email })) {
      return see(signupError('exists'));
    }
    const user = await users.create({ email, name, passwordHash: hashPassword(password) });
    return openSession(req, sessions, user.id);
  }

  /** POST handler — destroy the session (DB + cookie). */
  async function logout(req: NextRequest) {
    const token = req.cookies.get(cookie)?.value;
    if (token) {
      const { sessions } = await config.getRepos();
      const session = await sessions.findOne({ token });
      if (session) await sessions.delete(session.id);
    }
    const res = see(afterLogout);
    res.cookies.delete(cookie);
    return res;
  }

  return { login, signup, logout };
}

// ---------------------------------------------------------------------------
// getCurrentUser — read the session in Server Components.
// `cookies()` MUST be the first `await` (no preceding await/import) so the
// request scope survives in WebContainers.
// ---------------------------------------------------------------------------

export function createGetCurrentUser<TUser = unknown>(config: AuthLiteConfig) {
  const cookie = config.cookieName ?? 'session';
  return async function getCurrentUser(): Promise<TUser | null> {
    const token = (await cookies()).get(cookie)?.value;
    if (!token) return null;
    const { sessions } = await config.getRepos();
    const session = await sessions.findOne({ token });
    if (!session) return null;
    if (new Date(session.expiresAt) < new Date()) return null;
    const populated = (await sessions.findByIdWithRelations(session.id, ['user'])) as { user?: TUser } | null;
    return populated?.user ?? null;
  };
}
