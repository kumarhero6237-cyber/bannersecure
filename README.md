# info-banner-merge

## Advanced API Key + Domain Lock Admin

Set these environment variables before deployment:
- Admin password is securely stored as a PBKDF2-HMAC-SHA256 hash; plaintext password is not stored in the project.
- `ADMIN_SESSION_SECRET` — optional long random Flask session secret override
- Optional: `API_KEYS_FILE` — path to the JSON key database (default `api_keys.json`)

Open `/admin` to generate keys. Each key is bound to exactly one hostname. The API rejects:
- missing/invalid keys
- disabled keys
- requests with no browser Origin/Referer
- requests coming from a different hostname

Example browser usage:
`/uc-info?uid=123456789&key=RAVEN-...`

For production/serverless deployment, `api_keys.json` must be on persistent storage. Vercel's normal filesystem is ephemeral, so use a persistent database/KV layer if the project is deployed there. Do not rely on the default empty JSON file for durable production key management.
