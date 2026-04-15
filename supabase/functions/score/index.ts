// Tenzo Flappy — score Edge Function
// Handles two actions:
//   token  → signs a score proof (called at game death, before name entry)
//   submit → verifies proof and inserts into leaderboard (called on POST)
//
// Deploy:  supabase functions deploy score
// Secret:  supabase secrets set SCORE_SIGNING_KEY=<random string>

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

const SIGNING_KEY        = Deno.env.get('SCORE_SIGNING_KEY') ?? ''
const SUPABASE_URL       = Deno.env.get('SUPABASE_URL') ?? ''
const SUPABASE_SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''

const TOKEN_TTL_MS = 10 * 60 * 1000  // token expires after 10 minutes

const CORS = {
  'Access-Control-Allow-Origin':  '*',
  'Access-Control-Allow-Headers': 'content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  })
}

async function hmacHex(key: string, data: string): Promise<string> {
  const enc = new TextEncoder()
  const k = await crypto.subtle.importKey(
    'raw', enc.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', k, enc.encode(data))
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null, { headers: CORS })
  if (req.method !== 'POST')    return json({ error: 'method not allowed' }, 405)

  let body: Record<string, unknown>
  try { body = await req.json() } catch { return json({ error: 'invalid json' }, 400) }

  const { action } = body

  // ── TOKEN ────────────────────────────────────────────────────────────────
  // Called right after the player dies. Returns a signed proof tied to the score.
  if (action === 'token') {
    const score = Number(body.score)
    if (!Number.isInteger(score) || score <= 0) return json({ error: 'invalid score' }, 400)

    const nonce = crypto.randomUUID()
    const ts    = Date.now()
    const token = await hmacHex(SIGNING_KEY, `${score}:${nonce}:${ts}`)
    return json({ token, nonce, ts })
  }

  // ── SUBMIT ───────────────────────────────────────────────────────────────
  // Called when the player clicks POST. Verifies the proof before inserting.
  if (action === 'submit') {
    const score = Number(body.score)
    const name  = typeof body.name === 'string' ? body.name.trim() : ''
    const { token, nonce, ts } = body as { token: string; nonce: string; ts: number }

    if (!name || name.length > 30)              return json({ error: 'invalid name' }, 400)
    if (!Number.isInteger(score) || score <= 0) return json({ error: 'invalid score' }, 400)
    if (!token || !nonce || !ts)                return json({ error: 'missing proof' }, 400)

    // Check token hasn't expired
    if (Date.now() - Number(ts) > TOKEN_TTL_MS) return json({ error: 'token expired — play again' }, 400)

    // Verify HMAC — proves this exact score was signed by this server
    const expected = await hmacHex(SIGNING_KEY, `${score}:${nonce}:${ts}`)
    if (token !== expected) return json({ error: 'invalid token' }, 403)

    // Insert using service role (bypasses RLS — anon INSERT is revoked)
    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    const { error } = await supabase.from('leaderboard').insert({ name, score })
    if (error) {
      console.error('insert error:', error)
      return json({ error: 'db error' }, 500)
    }

    return json({ ok: true })
  }

  return json({ error: 'unknown action' }, 400)
})
