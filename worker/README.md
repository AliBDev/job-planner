# Reg lookup (Cloudflare Worker, DVSA MOT History API)

Lets the job form fill in a car's make, model, colour, year, fuel, engine size and MOT date from its reg.
The DVSA credentials live only in this Worker. The Worker only answers signed-in users of the
`custom-remaps-planner` Firebase project, and only requests coming from https://alibdev.github.io.

It calls `GET https://history.mot.api.gov.uk/v1/trade/vehicles/registration/<reg>` with a Microsoft
OAuth token (client credentials, scope `https://tapi.dvsa.gov.uk/.default`) plus your `X-API-Key`.
Tokens are cached for about 18 minutes. DVSA revokes the API key if it goes **unused for 90 days**.

## One-off setup
1. **DVSA credentials**: the email from DVSA gives you a client ID, client secret, API key and a token URL (contains your tenant ID).
2. **Cloudflare**: create a free account at https://dash.cloudflare.com.
3. In a terminal in this `worker` folder (each command asks you to paste the value, so it never goes in a file or chat):
   ```
   npx wrangler login
   npx wrangler secret put DVSA_TOKEN_URL
   npx wrangler secret put DVSA_CLIENT_ID
   npx wrangler secret put DVSA_CLIENT_SECRET
   npx wrangler secret put DVSA_API_KEY
   npx wrangler deploy
   ```
   Deploy prints an address like `https://custom-remaps-dvla.<your-name>.workers.dev`.
4. Put that address into `DVLA_LOOKUP_URL` near the top of `index.html`, commit and merge.
   While it is empty the Look up button stays hidden, so nothing breaks in the meantime.

## Check the mapping against a real response
The field mapping is tolerant (`mapVehicle` in `index.js`) but was written without a live sample.
After deploying, look up a real reg in the app; if make, model or MOT date are blank, send the raw DVSA response (no secrets) so the mapping can be tightened.

## Tests
`node test.mjs` (sign-in verification, origin check, token caching/refresh and DVSA mapping with fake tokens).
