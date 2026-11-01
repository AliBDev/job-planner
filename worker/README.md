# DVLA reg lookup (Cloudflare Worker)

Lets the job form fill in a car's make, colour, year, fuel, engine size and MOT date from its reg.
The DVLA key lives only in this Worker. The Worker only answers signed-in users of the
`custom-remaps-planner` Firebase project, and only requests coming from https://alibdev.github.io.

DVLA's free service returns the **make, not the model**, so the app fills the make and you add the model.

## One-off setup
1. **DVLA key**: apply at https://register-for-ves.driver-vehicle-licensing.api.gov.uk/ (Vehicle Enquiry Service). They email a key, usually within a few days.
2. **Cloudflare**: create a free account at https://dash.cloudflare.com.
3. In a terminal in this `worker` folder:
   ```
   npx wrangler login
   npx wrangler secret put DVLA_API_KEY      # paste the key when asked
   npx wrangler deploy
   ```
   Deploy prints an address like `https://custom-remaps-dvla.<your-name>.workers.dev`.
4. Put that address into `DVLA_LOOKUP_URL` near the top of `index.html` in the app, commit and merge.
   While it is empty the Look up button stays hidden, so nothing breaks in the meantime.

## Tests
`node test.mjs` (checks sign-in verification, origin check and DVLA mapping with fake tokens).
