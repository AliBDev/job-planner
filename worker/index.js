/* Custom Remaps: reg lookup proxy (Cloudflare Worker) using the DVSA MOT History API
   - keeps the DVSA credentials on the server, never in the app
   - only answers signed-in users of the Firebase project (checks the Firebase ID token)
   - only answers requests from the allowed app origin(s) */

const DVSA_URL = 'https://history.mot.api.gov.uk/v1/trade/vehicles/registration/';
const DVSA_SCOPE = 'https://tapi.dvsa.gov.uk/.default';
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

let dvsaTok = { at: 0, exp: 0, value: '' };
async function dvsaToken(env, fetchFn, force) {
  if (!force && dvsaTok.value && Date.now() < dvsaTok.exp) return dvsaTok.value;
  const r = await fetchFn(env.DVSA_TOKEN_URL, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', client_id: env.DVSA_CLIENT_ID, client_secret: env.DVSA_CLIENT_SECRET, scope: DVSA_SCOPE }).toString() });
  if (!r.ok) throw new Error('dvsa_token');
  const j = await r.json();
  if (!j.access_token) throw new Error('dvsa_token');
  dvsaTok = { at: Date.now(), exp: Date.now() + Math.max(60, (Number(j.expires_in) || 1200) - 120) * 1000, value: j.access_token };
  return dvsaTok.value;
}
const dvsaGet = (reg, env, fetchFn, tok) => fetchFn(DVSA_URL + encodeURIComponent(reg), { method: 'GET', headers: { Authorization: 'Bearer ' + tok, 'X-API-Key': env.DVSA_API_KEY, Accept: 'application/json' } });
const dateOnly = v => { const m = String(v || '').match(/^(\d{4})[-.\/](\d{2})[-.\/](\d{2})/); return m ? m[1] + '-' + m[2] + '-' + m[3] : ''; };
/* Tolerant mapping: DVSA has used slightly different field names across versions. */
export function mapVehicle(raw, reg) {
  const d = Array.isArray(raw) ? (raw[0] || {}) : (raw || {});
  const tests = Array.isArray(d.motTests) ? d.motTests : [];
  const today = new Date().toISOString().slice(0, 10);
  const exps = tests.filter(t => !t.testResult || /pass/i.test(t.testResult)).map(t => dateOnly(t.expiryDate)).filter(Boolean).sort();
  let motExpiry = dateOnly(d.motTestExpiryDate || d.motExpiryDate || d.motExpiry) || exps[exps.length - 1] || '';
  const due = dateOnly(d.motTestDueDate);
  if (!motExpiry && due) motExpiry = due;
  const first = dateOnly(d.firstUsedDate || d.registrationDate || d.dateOfFirstRegistration);
  const year = Number(d.manufactureYear) || (first ? Number(first.slice(0, 4)) : null);
  return {
    reg: d.registration || d.registrationNumber || reg, make: d.make || '', model: d.model || '', colour: d.primaryColour || d.colour || '',
    year: year || null, fuel: d.fuelType || '', cc: Number(d.engineSize || d.engineCapacity) || null,
    motExpiry: motExpiry, motStatus: motExpiry ? (motExpiry >= today ? 'Valid' : 'Expired') : ''
  };
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
      let tok = await dvsaToken(env, fetchFn, false);
      r = await dvsaGet(reg, env, fetchFn, tok);
      if (r.status === 401) { tok = await dvsaToken(env, fetchFn, true); r = await dvsaGet(reg, env, fetchFn, tok); }
    } catch (e) { return send(502, { error: 'dvsa_unreachable' }); }
    if (r.status === 404) return send(404, { error: 'not_found' });
    if (r.status === 400) return send(400, { error: 'bad_reg' });
    if (r.status === 429) return send(429, { error: 'busy' });
    if (!r.ok) return send(502, { error: 'dvsa_error' });
    let d; try { d = await r.json(); } catch (e) { return send(502, { error: 'dvsa_error' }); }
    return send(200, mapVehicle(d, reg));
  }
};
