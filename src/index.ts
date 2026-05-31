/**
 * @mostajs/auth-lite — minimal, dependency-free email/password + session auth
 * for Next.js (App Router) on top of @mostajs/orm.
 *
 * Why "lite": it boots in WebContainers (Bolt.new / StackBlitz) and the edge —
 * no native addon (no bcrypt/argon2), and it sets the session cookie on the
 * NextResponse object inside Route Handlers, which sidesteps the AsyncLocalStorage
 * pitfalls of `cookies()` after a DB call in constrained runtimes.
 *
 * Password hashing is salted, iterated SHA-256 (works everywhere). For a
 * production server you can swap in argon2/scrypt — the API is unchanged.
 *
 * @author Dr Hamid MADANI <drmdh@msn.com>
 */
// Types only — érasés au runtime (aucun import next au top-level → le module se
// charge en Node/edge/WebContainer ; NextResponse/cookies sont importés
// dynamiquement DANS les handlers, qui ne tournent que dans le runtime Next).
import type { NextRequest } from 'next/server';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import type { EntitySchema } from '@mostajs/orm';
import { baseFromHeaders } from '@mostajs/url';

/**
 * Base PUBLIQUE (`proto://host`) pour les redirects. En WebContainer
 * (StackBlitz/Bolt) ou derrière un reverse proxy, `req.url` côté Node pointe
 * sur le bind interne (`http://localhost:3000`) → l'utilisateur serait redirigé
 * vers localhost. `baseFromHeaders` lit l'hôte public réel depuis
 * `X-Forwarded-Host`/`Host` ; fallback sur l'origine de `req.url`.
 */
function reqBase(req: NextRequest): string {
  return baseFromHeaders(req.headers) ?? new URL(req.url).origin;
}

// ---------------------------------------------------------------------------
// Password hashing — salted, iterated SHA-256 (no native addon, boots anywhere)
// ---------------------------------------------------------------------------

const ITERATIONS = 10_000;

function derive(password: string, salt: string): Buffer {
  let h = createHash('sha256').update(`${salt}:${password}`).digest();
  for (let i = 0; i < ITERATIONS; i++) h = createHash('sha256').update(h).digest();
  return h;
}

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  return `${salt}:${derive(password, salt).toString('hex')}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const [salt, hashHex] = stored.split(':');
  if (!salt || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = derive(password, salt);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

// ---------------------------------------------------------------------------
// Default Session EntitySchema — register it alongside your own `User` entity
// (User must have at least `email` (unique) and `passwordHash`; `name` for signup).
// ---------------------------------------------------------------------------

export const SessionSchema: EntitySchema = {
  name: 'Session',
  collection: 'sessions',
  fields: {
    token: { type: 'string', required: true, unique: true },
    expiresAt: { type: 'date', required: true },
  },
  relations: {
    user: { target: 'User', type: 'many-to-one', required: true, onDelete: 'cascade' },
  },
  indexes: [{ fields: ['token'], unique: true }],
  timestamps: true,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Minimal repository shape this module needs (compatible with @mostajs/orm BaseRepository). */
export interface AuthRepo {
  findOne(filter: Record<string, unknown>): Promise<any>;
  create(data: Record<string, unknown>): Promise<any>;
  delete(id: string): Promise<unknown>;
  findByIdWithRelations(id: string, relations: string[], options?: unknown): Promise<any>;
}

export interface AuthLiteConfig {
  /** Returns the User + Session repositories (e.g. your getRepos()). */
  getRepos: () => Promise<{ users: AuthRepo; sessions: AuthRepo }>;
  /** Session cookie name (default "session"). */
  cookieName?: string;
  /** Session lifetime in days (default 7). */
  ttlDays?: number;
  /** Where to go after login/signup (default "/dashboard"). */
  afterAuth?: string;
  /** Where to go after logout (default "/"). */
  afterLogout?: string;
  /** Redirect on invalid login (default "/login?error=invalid"). */
  loginErrorPath?: string;
  /** Redirect on signup error (default "/signup?error=<kind>"). */
  signupErrorPath?: (kind: 'invalid' | 'exists') => string;
}

// ---------------------------------------------------------------------------
// Route Handlers — login / signup / logout (set the cookie on the response)
// ---------------------------------------------------------------------------

export function createAuthHandlers(config: AuthLiteConfig) {
  const cookie = config.cookieName ?? 'session';
  const ttlMs = (config.ttlDays ?? 7) * 86400000;
  const afterAuth = config.afterAuth ?? '/dashboard';
  const afterLogout = config.afterLogout ?? '/';
  const loginError = config.loginErrorPath ?? '/login?error=invalid';
  const signupError = config.signupErrorPath ?? ((k: 'invalid' | 'exists') => `/signup?error=${k}`);

  async function startSession(req: NextRequest, sessions: AuthRepo, userId: string) {
    const { NextResponse } = await import('next/server');
    const token = randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + ttlMs);
    await sessions.create({ token, user: userId, expiresAt });
    const res = NextResponse.redirect(new URL(afterAuth, reqBase(req)), 303);
    res.cookies.set(cookie, token, { httpOnly: true, sameSite: 'lax', path: '/', expires: expiresAt });
    return res;
  }

  /** POST handler — verify credentials, start a session. */
  async function login(req: NextRequest) {
    const { NextResponse } = await import('next/server');
    const form = await req.formData();
    const email = String(form.get('email') ?? '').toLowerCase().trim();
    const password = String(form.get('password') ?? '');
    const { users, sessions } = await config.getRepos();
    const user = await users.findOne({ email });
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return NextResponse.redirect(new URL(loginError, reqBase(req)), 303);
    }
    return startSession(req, sessions, user.id);
  }

  /** POST handler — create the account, start a session. */
  async function signup(req: NextRequest) {
    const { NextResponse } = await import('next/server');
    const form = await req.formData();
    const email = String(form.get('email') ?? '').toLowerCase().trim();
    const name = String(form.get('name') ?? '').trim();
    const password = String(form.get('password') ?? '');
    if (!email || !name || password.length < 6) {
      return NextResponse.redirect(new URL(signupError('invalid'), reqBase(req)), 303);
    }
    const { users, sessions } = await config.getRepos();
    if (await users.findOne({ email })) {
      return NextResponse.redirect(new URL(signupError('exists'), reqBase(req)), 303);
    }
    const user = await users.create({ email, name, passwordHash: hashPassword(password) });
    return startSession(req, sessions, user.id);
  }

  /** POST handler — destroy the session (DB + cookie). */
  async function logout(req: NextRequest) {
    const { NextResponse } = await import('next/server');
    const token = req.cookies.get(cookie)?.value;
    if (token) {
      const { sessions } = await config.getRepos();
      const session = await sessions.findOne({ token });
      if (session) await sessions.delete(session.id);
    }
    const res = NextResponse.redirect(new URL(afterLogout, reqBase(req)), 303);
    res.cookies.delete(cookie);
    return res;
  }

  return { login, signup, logout };
}

// ---------------------------------------------------------------------------
// getCurrentUser — read the session in Server Components (cookie read before DB)
// ---------------------------------------------------------------------------

export function createGetCurrentUser<TUser = unknown>(config: AuthLiteConfig) {
  const cookie = config.cookieName ?? 'session';
  return async function getCurrentUser(): Promise<TUser | null> {
    const { cookies } = await import('next/headers');
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
