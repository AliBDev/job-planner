import worker, { verifyFirebaseToken, mapVehicle, keepAlive } from './index.js';
import { webcrypto } from 'node:crypto';
const PID = 'custom-remaps-planner';
const kp = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' }, true, ['sign','verify']);
const jwk = Object.assign(await crypto.subtle.exportKey('jwk', kp.publicKey), { kid: 'k1', alg: 'RS256', use: 'sig' });
const b64 = o => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
async function token(over = {}, kid = 'k1') {
  const now = Math.floor(Date.now() / 1000);
  const h = b64({ alg: 'RS256', kid, typ: 'JWT' });
  const p = b64(Object.assign({ aud: PID, iss: 'https://securetoken.google.com/' + PID, sub: 'u1', iat: now - 5, exp: now + 3600 }, over));
  const sig = Buffer.from(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', kp.privateKey, new TextEncoder().encode(h + '.' + p))).toString('base64url');
  return h + '.' + p + '.' + sig;
}
let dvlaCalls = [], tokenCalls = 0;
const fakeFetch = async (url, init) => {
  const u = String(url);
  if (u.includes('googleapis.com')) return new Response(JSON.stringify({ keys: [jwk] }), { status: 200 });
  if (u.startsWith('https://login.example/')) { tokenCalls++; return new Response(JSON.stringify({ access_token: 'tok' + tokenCalls, expires_in: 1199 }), { status: 200 }); }
  dvlaCalls.push({ url: u, init });
  const reg = decodeURIComponent(u.split('/').pop());
  if (reg === 'NOPE1') return new Response('{}', { status: 404 });
  if (reg === 'EXPIRE1' && init.headers.Authorization === 'Bearer tok1') return new Response('{}', { status: 401 });
  return new Response(JSON.stringify({ registration: reg, make: 'VOLKSWAGEN', model: 'GOLF', primaryColour: 'Grey', fuelType: 'Petrol', engineSize: '1984', firstUsedDate: '2019.03.01',
    motTests: [{ testResult: 'FAILED', completedDate: '2024.02.01' }, { testResult: 'PASSED', expiryDate: '2099-03-01' }] }), { status: 200 });
};
const env = { DVSA_API_KEY: 'secret-key', DVSA_CLIENT_ID: 'cid', DVSA_CLIENT_SECRET: 'csecret', DVSA_TOKEN_URL: 'https://login.example/t/oauth2/v2.0/token', FIREBASE_PROJECT_ID: PID, ALLOWED_ORIGIN: 'https://alibdev.github.io' };
const req = (tok, body, origin = 'https://alibdev.github.io', method = 'POST') => new Request('https://w.example/', { method, headers: { Origin: origin, Authorization: tok ? 'Bearer ' + tok : '', 'Content-Type': 'application/json' }, body: method === 'POST' ? JSON.stringify(body) : undefined });
let fails = 0; const ok = (c, m) => { console.log((c ? 'PASS ' : 'FAIL ') + m); if (!c) fails++; };
const run = (r) => worker.fetch(r, env, {}, fakeFetch);
let r = await run(req(await token(), { reg: 'yx19 ktl' }));
ok(r.status === 200, 'valid token + reg -> 200'); const j = await r.json(); ok(j.make === 'VOLKSWAGEN' && j.model === 'GOLF' && j.year === 2019 && j.cc === 1984 && j.motExpiry === '2099-03-01' && j.motStatus === 'Valid', 'returns mapped fields incl. model');
ok(dvlaCalls[0].init.headers['X-API-Key'] === 'secret-key' && dvlaCalls[0].init.headers.Authorization === 'Bearer tok1' && dvlaCalls[0].url.endsWith('/registration/YX19KTL'), 'bearer + key sent to DVSA, reg normalised');
ok(!JSON.stringify(j).includes('secret-key') && !JSON.stringify(j).includes('csecret'), 'secrets never in response');
await run(req(await token(), { reg: 'AB12CDE' })); ok(tokenCalls === 1, 'DVSA token cached between lookups');
r = await run(req(await token(), { reg: 'EXPIRE1' })); ok(r.status === 200 && tokenCalls === 2, 'expired DVSA token is refreshed and retried');
ok(r.headers.get('Access-Control-Allow-Origin') === 'https://alibdev.github.io', 'CORS header');
ok((await run(req('', { reg: 'AB12CDE' }))).status === 401, 'no token -> 401');
ok((await run(req(await token({ exp: 1 }), { reg: 'AB12CDE' }))).status === 401, 'expired token -> 401');
ok((await run(req(await token({ aud: 'other' }), { reg: 'AB12CDE' }))).status === 401, 'wrong project -> 401');
const t = await token(); ok((await run(req(t.slice(0, -4) + 'AAAA', { reg: 'AB12CDE' }))).status === 401, 'tampered signature -> 401');
ok((await run(req(await token({}, 'zzz'), { reg: 'AB12CDE' }))).status === 401, 'unknown key id -> 401');
const n = dvlaCalls.length; ok((await run(req(await token(), { reg: 'AB12CDE' }, 'https://evil.example'))).status === 403 && dvlaCalls.length === n, 'wrong origin -> 403, DVSA not called');
ok((await run(req(await token(), { reg: '!' }))).status === 400, 'bad reg -> 400');
ok((await run(req(await token(), { reg: 'NOPE1' }))).status === 404, 'unknown reg -> 404');
ok((await run(req(null, null, 'https://alibdev.github.io', 'OPTIONS'))).status === 204, 'preflight 204');
ok((await run(req(null, null, 'https://alibdev.github.io', 'GET'))).status === 405, 'GET -> 405');
const mv = mapVehicle([{ registration: 'X', make: 'FORD', model: 'FOCUS', primaryColour: 'Blue', fuelType: 'Diesel', engineSize: 1560, registrationDate: '2015-06-02', motTestDueDate: '2027-06-01' }], 'X'); ok(mv.model === 'FOCUS' && mv.year === 2015 && mv.motExpiry === '2027-06-01', 'tolerant mapping handles array + alternative field names');
const before = dvlaCalls.length;
ok(await keepAlive(env, fakeFetch) === true && dvlaCalls.length === before + 1 && dvlaCalls[before].url.endsWith('/registration/AB12CDE'), 'keep-alive makes one DVSA lookup');
ok(await keepAlive(Object.assign({}, env, { KEEPALIVE_REG: 'NOPE1' }), fakeFetch) === true, 'keep-alive treats not-found as success (key accepted)');
ok(await keepAlive(env, async () => new Response('x', { status: 500 })) === false, 'keep-alive reports failure on server error');
ok(await keepAlive(env, async () => { throw new Error('net'); }) === false, 'keep-alive does not throw on network failure');
const b2 = dvlaCalls.length; await worker.scheduled({ cron: '17 6 1 * *' }, env, {}, fakeFetch); ok(dvlaCalls.length === b2 + 1, 'scheduled handler runs the keep-alive lookup');
console.log(fails ? fails + ' FAILED' : 'ALL PASSED');
