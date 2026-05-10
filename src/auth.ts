import { D1Adapter } from '@auth/d1-adapter'
import GitHub from '@auth/core/providers/github'
import Credentials from '@auth/core/providers/credentials'
import type { ConfigHandler } from '@hono/auth-js'
import { verifyPassword } from './crypto'

export type Env = {
  DB: D1Database
  AUTH_SECRET: string
  GITHUB_CLIENT_ID: string
  GITHUB_CLIENT_SECRET: string
  CORS_ORIGIN: string
}

export const authConfig: ConfigHandler = (c) => {
  const env = c.env as Env

  return {
    adapter: D1Adapter(env.DB),
    providers: [
      GitHub({
        clientId: env.GITHUB_CLIENT_ID,
        clientSecret: env.GITHUB_CLIENT_SECRET,
      }),
      Credentials({
        credentials: {
          email: { label: 'Email', type: 'email' },
          password: { label: 'Password', type: 'password' },
        },
        async authorize(credentials) {
          if (!credentials?.email || !credentials?.password) return null
          const user = await env.DB.prepare('SELECT id, name, email, password FROM users WHERE email = ?')
            .bind(credentials.email)
            .first<{ id: string; name: string | null; email: string; password: string | null }>()
          if (!user?.password) return null
          const valid = await verifyPassword(credentials.password as string, user.password)
          if (!valid) return null
          return { id: user.id, name: user.name, email: user.email }
        },
      }),
    ],
    session: { strategy: 'jwt' },
    // Required for Cloudflare Workers — not auto-detected unlike Pages/Vercel
    trustHost: true,
    callbacks: {
      async jwt({ token, user }) {
        if (user) token.sub = user.id
        return token
      },
      async session({ session, token }) {
        if (token.sub) session.user.id = token.sub
        return session
      },
    },
  }
}
                                                    