# Suru Traffic Backend (personal use)

API-only starter. No frontend or unnecessary marketing pages.

## Free setup
- API hosting: Render free Web Service (`*.onrender.com` subdomain)
- PostgreSQL: Neon Free (`neon.tech`)
- Cron: GitHub Actions workflow every 10 minutes. Scheduled jobs can be delayed; it is not exact-time cron.
- No paid domain needed for testing.

## Deploy
1. Create a Neon PostgreSQL project and copy its connection string.
2. Upload all files in this ZIP to a PRIVATE GitHub repository. Keep `.github/workflows/sync-orders.yml`.
3. In Render, create a Web Service connected to that repo. Build: `npm install`; Start: `npm start`.
4. Set Render environment variables:
   - `DATABASE_URL`: Neon connection string
   - `JWT_SECRET`: random string, 32+ characters
   - `CRON_SECRET`: a different random secret
   - `ADMIN_EMAIL`: your email
   - `ADMIN_PASSWORD`: strong password, 12+ characters
   - `NODE_ENV`: `production`
5. Initialize schema/admin once. If Render Shell is available, run `npm run db:init`. Otherwise temporarily set Start Command to `npm run db:init && npm start`, deploy once, check logs for `Schema ready` and `Admin created`, then restore Start Command to `npm start` and redeploy. This command does not delete data or reset existing admin passwords.
6. In GitHub repo → Settings → Secrets and variables → Actions, add:
   - `SURU_API_URL` = Render URL, e.g. `https://your-api.onrender.com`
   - `SURU_CRON_SECRET` = exactly the same as Render's `CRON_SECRET`
7. In Actions, run **Sync provider orders** manually once to test.

## API
Base URL: `https://your-api.onrender.com`; `/api` lists endpoints.

Login:
`POST /api/auth/login` JSON `{"email":"you@example.com","password":"your-password"}`.
Send returned token as `Authorization: Bearer TOKEN`.

Add provider (admin token):
`POST /api/admin/providers` JSON `{"name":"Provider","api_url":"https://provider.example/api/v2","api_key":"YOUR_KEY"}`.

Add service (admin token):
`POST /api/admin/services` JSON `{"provider_id":1,"provider_service_id":"123","category":"Social","name":"Service name","cost_per_1000":1,"price_per_1000":1.5,"min_qty":100,"max_qty":10000}`.

Place order (user token):
`POST /api/orders` JSON `{"service_id":1,"link":"https://example.com/target","quantity":100}`.

Wallet: users can submit manual deposit records using `POST /api/deposits`; admin reviews with `GET /api/admin/deposits` and `POST /api/admin/deposits/:id/decision` JSON `{"decision":"approve"}`. Admin can also credit/debit using `POST /api/admin/wallet-adjust` JSON `{"user_id":2,"amount":10}`.

Provider API format: common SMM API `action=add` and `action=status`.

## Notes
- This is a backend, not a visual dashboard. Use Postman/Thunder Client until you connect a frontend.
- Render free web services may sleep while idle; GitHub cron can be delayed. Neon and Render free tiers have usage limits.
- Provider API keys stay server-side. Never commit secrets.
- Use providers/services you are authorized to resell and follow platform terms.
