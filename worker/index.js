/* Custom Remaps: DVLA reg lookup proxy (Cloudflare Worker)
   - keeps the DVLA API key on the server, never in the app
   - only answers signed-in users of the Firebase project (checks the Firebase ID token)
   - only answers requests from the allowed app origin(s) */

const DVLA_URL = 'https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles';
const JWKS_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';

let jwksCache = { at: 0, keys: null };

const b64urlToBytes = s => {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const b64urlToJson = s => JSON.parse(new TextDecoder().decode(b64urlToBytes(s)));

async function getKeys(fetchFn) {
  if (jwksCache.keys && Date.now() - jwksCache.at < 3600e3) return jwksCache.keys;
  const r = await fetchFn(JWKS_URL);
  if (!r.ok) throw new Error('jwks');
  jwksCache = { at: Date.now(), keys: (await r.json()).keys || [] };
  return jwksCache.keys;
}

export async function verifyFirebaseToken(token, projectId, fetchFn = fetch, nowMs = Date.now()) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let header, claims;
  try { header = b64urlToJson(parts[0]); claims = b64urlToJson(parts[1]); } catch (e) { return null; }
  if (header.alg !== 'RS256' || !header.kid) return null;
  const now = Math.floor(nowMs / 1000);
  if (claims.aud !== projectId || claims.iss !== 'https://securetoken.google.com/' + projectId) return null;
  if (!claims.sub || typeof claims.exp !== 'number' || claims.exp <= now || (claims.iat && claims.iat > now + 300)) return null;
  const jwk = (await getKeys(fetchFn)).find(k => k.kid === header.kid);
  if (!jwk) return null;
  const key = await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64urlToBytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  return ok ? claims : null;
}

const normReg = r => String(r || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

export default {
  async fetch(request, env, ctx, fetchFn = fetch) {
    const allowed = String(env.ALLOWED_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
    const origin = request.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': allowed.includes(origin) ? origin : (allowed[0] || ''),
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin'
    };
    const send = (status, body) => new Response(JSON.stringify(body), { status, headers: Object.assign({ 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, cors) });

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method !== 'POST') return send(405, { error: 'method' });
    if (!allowed.includes(origin)) return send(403, { error: 'origin' });

    const auth = request.headers.get('Authorization') || '';
    let claims = null;
    try { claims = await verifyFirebaseToken(auth.replace(/^Bearer\s+/i, ''), env.FIREBASE_PROJECT_ID, fetchFn); } catch (e) { return send(502, { error: 'auth_unavailable' }); }
    if (!claims) return send(401, { error: 'signin' });

    let reg = '';
    try { reg = normReg((await request.json()).reg); } catch (e) { /* fall through */ }
    if (reg.length < 2 || reg.length > 8) return send(400, { error: 'bad_reg' });

    let r;
    try {
      r = await fetchFn(DVLA_URL, { method: 'POST', headers: { 'x-api-key': env.DVLA_API_KEY, 'Content-Type': 'application/json' }, body: JSON.stringify({ registrationNumber: reg }) });
    } catch (e) { return send(502, { error: 'dvla_unreachable' }); }
    if (r.status === 404) return send(404, { error: 'not_found' });
    if (r.status === 400) return send(400, { error: 'bad_reg' });
    if (r.status === 429) return send(429, { error: 'busy' });
    if (!r.ok) return send(502, { error: 'dvla_error' });
    const d = await r.json();
    return send(200, {
      reg: d.registrationNumber || reg, make: d.make || '', colour: d.colour || '', year: d.yearOfManufacture || null,
      fuel: d.fuelType || '', cc: d.engineCapacity || null, taxStatus: d.taxStatus || '', taxDue: d.taxDueDate || '',
      motStatus: d.motStatus || '', motExpiry: d.motExpiryDate || ''
    });
  }
};
