/**
 * @mostajs/auth-lite — minimal email/password + session auth on @mostajs/orm.
 *
 * This entry (`@mostajs/auth-lite`) is the **framework-agnostic core** :
 * password hashing + the `Session` schema + the shared types. It imports
 * **no `next`**, so it loads in Node / edge / WebContainer and is unit-testable.
 *
 * The **Next.js adapter** (Route Handlers + `getCurrentUser`) lives in the
 * `@mostajs/auth-lite/next` subpath — it statically imports `next/server` and
 * `next/headers` so that `cookies()` is the first `await` (request scope intact
 * in WebContainers).
 *
 * Password hashing is salted, iterated SHA-256 (no native addon — boots
 * everywhere). For a production server you can swap in argon2/scrypt; the API
 * is unchanged.
 *
 * @author Dr Hamid MADANI <drmdh@msn.com>
 */
import { createHash, randomBytes, timingSafeEqual } from 'crypto';
import type { EntitySchema } from '@mostajs/orm';

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
// Config / shared types
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
