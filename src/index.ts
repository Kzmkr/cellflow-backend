import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { authHandler, initAuthConfig, verifyAuth } from '@hono/auth-js'
import { authConfig, type Env } from './auth'
import { hashPassword } from './crypto'

const app = new Hono()

app.use('*', (c, next) => {
  const env = c.env as Env
  return cors({ origin: env.CORS_ORIGIN ?? '*', credentials: true })(c, next)
})
app.use('*', initAuthConfig(authConfig))
app.use('/api/auth/*', authHandler())

app.get('/', (c) => c.json({ status: 'ok' }))

app.post('/api/register', async (c) => {
  const { email, password, name } = await c.req.json<{ email: string; password: string; name?: string }>()
  if (!email || !password) return c.json({ error: 'Email and password required' }, 400)

  const env = c.env as Env
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (existing) return c.json({ error: 'User already exists' }, 409)

  const id = crypto.randomUUID()
  const hash = await hashPassword(password)
  await env.DB.prepare('INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)')
    .bind(id, name ?? null, email, hash)
    .run()

  return c.json({ success: true }, 201)
})

app.get('/api/me', verifyAuth(), (c) => {
  const auth = c.get('authUser')
  return c.json({ user: auth.session.user })
})

export default app
