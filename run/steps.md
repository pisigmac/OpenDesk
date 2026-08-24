Auth is not a Cloudflare Worker. It is a long-running FastAPI process + Postgres. You put Cloudflare in front (DNS, TLS, WAF) and run Auth as an origin. Products never download Auth; they call https://auth.plexapps.com and cache JWKS.

Use your real zone name everywhere below (plexapps.com, plexapps.dev, …). The hostname to standardize on:

https://auth.plexapps.com

Never change AUTH_ISSUER after the first production token is issued. That value is the public URL.

───

0. What you are shipping

┌─────────────────────┬─────────────────────────┬──────────────────────────────────────┐
│ Piece               │ Where it lives          │ Who updates it                       │
├─────────────────────┼─────────────────────────┼──────────────────────────────────────┤
│ Auth API + admin UI │ Origin you run (Docker) │ You deploy a new image               │
├─────────────────────┼─────────────────────────┼──────────────────────────────────────┤
│ Postgres            │ Same host or managed DB │ You migrate                          │
├─────────────────────┼─────────────────────────┼──────────────────────────────────────┤
│ auth.plexapps.com   │ Cloudflare DNS → origin │ You point once                       │
├─────────────────────┼─────────────────────────┼──────────────────────────────────────┤
│ Product apps        │ Their own repos         │ They set baseUrl once                │
├─────────────────────┼─────────────────────────┼──────────────────────────────────────┤
│ TS SDK              │ Copied/imported client  │ Bump only when they want new methods │
└─────────────────────┴─────────────────────────┴──────────────────────────────────────┘

End users never install anything. Operators open https://auth.plexapps.com/admin/console.

───

1. Decide the origin (pick one)

Cloudflare will not execute opendesk-auth for you. You need a machine that can run Docker and keep port 8090 (or 443) reachable only by Cloudflare.

Practical options:

1. Small VPS (Hetzner, DigitalOcean, Lightsail) + Docker Compose — simplest, matches this repo.
2. Fly.io / Railway / Render — container from Auth/Dockerfile, attach Postgres.
3. Cloudflare Tunnel (cloudflared) on that VPS — no public 8090, Cloudflare connects out. Recommended if you do not want to open a firewall.

Do not use wrangler deploy on Auth. That path is for the Worker services (Mail, Billing, …).

Run one Auth replica for now. Rate limits are in-process memory; two containers will each have their own counters.

───

2. Create Cloudflare DNS (once)

In the plexapps zone:

1. Add an A or AAAA record
   • Name: auth
   • Value: VPS public IP
   • Proxy: Proxied (orange cloud)

   Or, if using Tunnel: create a Tunnel Public Hostname
   • Hostname: auth.plexapps.com
   • Service: http://127.0.0.1:8090
   No A record to the VPS is required.

2. SSL/TLS mode: Full (strict) once you have a cert on the origin, or Full if the origin is HTTP-only behind Tunnel (Tunnel terminates TLS at Cloudflare).

3. Always Use HTTPS: On.

4. Optional but useful:
   • WAF custom rule: rate-limit auth.plexapps.com/v1/auth/login
   • Bot Fight only if it does not break OAuth callbacks
   • Do not cache API paths (/v1/*, /introspect). Cache Level for this hostname: Bypass or a Cache Rule hostname eq auth.plexapps.com → Bypass.

5. Note Cloudflare’s connecting IPs. You will set AUTH_RATE_LIMIT_TRUST_PROXY=true so Auth reads CF-Connecting-IP or X-Forwarded-For. Prefer configuring the proxy header to cf-connecting-ip so you are not trusting a forged X-Forwarded-For.

───

3. Create production secrets (once, on your laptop)

Do this off the repo. Do not commit PEMs.

# RSA signing keys (keep private.pem offline + on the server only)
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem
openssl rsa -in private.pem -pubout -out public.pem

# One-time first-admin bootstrap
openssl rand -hex 32    # → AUTH_BOOTSTRAP_TOKEN

# Introspection (only if other backends will call /introspect)
openssl rand -hex 32    # → AUTH_INTROSPECTION_API_KEY

Store private.pem in the host secret store or /run/secrets/. Lose this file and every access token becomes unverifiable until you rotate keys (you only have one kid today).

───

4. Postgres

On the same VPS or a managed Postgres:

• Database name e.g. auth
• User/password not auth/auth
• Network: reachable from the Auth container only, not the public internet

Connection string Auth expects:

postgresql+psycopg://USER:PASSWORD@DB_HOST:5432/auth

Backups: enable daily snapshots before the first real user.

───

5. Run Auth on the origin

On the VPS, from a checkout of Auth/ (or a built image you pushed to GHCR/Docker Hub as yourorg/opendesk-auth:1.0.0):

1. Copy PEMs to the host, mode 600.
2. Set environment (example values — replace):

AUTH_DATABASE_URL=postgresql+psycopg://...
AUTH_ISSUER=https://auth.plexapps.com
AUTH_HOST=0.0.0.0
AUTH_PORT=8090

AUTH_JWT_PRIVATE_KEY_FILE=/run/secrets/auth_private.pem
AUTH_JWT_PUBLIC_KEY_FILE=/run/secrets/auth_public.pem
AUTH_JWT_KID=opendesk-auth-1

AUTH_OPEN_REGISTRATION=false
AUTH_BOOTSTRAP_TOKEN=<the hex you generated>
AUTH_REQUIRE_EMAIL_VERIFICATION=true

AUTH_CORS_ORIGINS=https://app.plexapps.com,https://auth.plexapps.com
AUTH_SPA_CALLBACK_URL=https://app.plexapps.com/auth/callback

AUTH_RATE_LIMIT_TRUST_PROXY=true
AUTH_RATE_LIMIT_PROXY_HEADER=cf-connecting-ip

AUTH_DEFAULT_AUDIENCES=          # or a product id if every signup should get that grant
AUTH_MAIL_BASE_URL=https://mail.plexapps.com    # if Mail worker is live
AUTH_MAIL_API_KEY=<mail key>

# OAuth only if you use Google/GitHub
AUTH_GOOGLE_CLIENT_ID=...
AUTH_GOOGLE_CLIENT_SECRET=...
AUTH_GOOGLE_REDIRECT_URI=https://auth.plexapps.com/v1/oauth/google/callback
AUTH_GITHUB_CLIENT_ID=...
AUTH_GITHUB_CLIENT_SECRET=...
AUTH_GITHUB_REDIRECT_URI=https://auth.plexapps.com/v1/oauth/github/callback

3. Start: docker compose up -d (after pointing compose env at the values above) or docker run of your tagged image with those env vars and PEM mounts.

4. Apply schema on first boot (create_all runs at startup). For an existing volume later:

docker compose exec auth python3 /app/migrations/run_migrations.py

(AUTH_DATABASE_URL must be in that container env.)

5. From the VPS: curl -sS http://127.0.0.1:8090/health
   Expect {"status":"ok",...}. If keys or DB are wrong you get 503.

6. From the internet: curl -sS https://auth.plexapps.com/health
   Same body. If this fails, DNS/SSL/Tunnel is wrong, not Auth.

7. Check JWKS: curl -sS https://auth.plexapps.com/.well-known/jwks.json
   You should see one RSA key, kid = opendesk-auth-1.

───

6. First platform admin (once)

Registration is closed. The first user must send the bootstrap token.

curl -sS https://auth.plexapps.com/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@plexapps.com","password":"<strong>","bootstrap_token":"<AUTH_BOOTSTRAP_TOKEN>"}'

If email verification is on, you get verification_required: true and no tokens. Verify via the mailed link (needs Mail live) or, only if Mail is not up yet, temporarily verify in the DB and turn Mail on before real users.

Then open:

https://auth.plexapps.com/admin/console

Sign in. You should see Overview / Users / Audit / System.

After this, rotate or delete AUTH_BOOTSTRAP_TOKEN so nobody else can claim a second “first admin” on a wiped DB. Keep AUTH_OPEN_REGISTRATION=false unless you intentionally want public signup.

───

7. OAuth apps (optional)

In Google Cloud / GitHub OAuth app settings, authorized redirect URLs must be exactly:

• https://auth.plexapps.com/v1/oauth/google/callback
• https://auth.plexapps.com/v1/oauth/github/callback

AUTH_SPA_CALLBACK_URL is where the browser lands after Auth (fragment with tokens), e.g. https://app.plexapps.com/auth/callback. That SPA must be listed in AUTH_CORS_ORIGINS.

───

8. Make it usable from products (the “no re-download” part)

Each product (web app, Worker, another service) does this once:

1. Config, not code:

AUTH_BASE_URL=https://auth.plexapps.com
AUTH_ISSUER=https://auth.plexapps.com

2. Send users to Auth (/v1/auth/login, OAuth start URLs, or your SPA that calls those).

3. Validate access tokens locally with JWKS from
   https://auth.plexapps.com/.well-known/jwks.json
   Check iss === https://auth.plexapps.com, aud contains your product id, exp valid.

4. If you use the TS client:

const auth = new OpenDesk Auth({ baseUrl: 'https://auth.plexapps.com' })

That is a config change in the product. They do not clone Auth. They do not download a new zip when you ship Auth 1.1.

5. Grant the product audience (admin console → user drawer → grant, or POST /v1/admin/grants) so JWT aud / roles include that product.

6. Other OpenDesk Auth Workers (Mail, Billing, …) stay on their own *.plexapps.com hostnames. Only Auth lives at auth..

───

9. How updates reach people who already use it

You ship a new Auth version (bugfix, new admin UI, new route):

1. Build/tag image opendesk-auth:1.1.0.
2. Run new migrations on the same Postgres.
3. Replace the container. Same hostname, same PEMs, same AUTH_ISSUER.
4. Every app already pointing at https://auth.plexapps.com gets the new API and /admin/console on next request. No product deploy required if /v1 did not break.

You add SDK methods (sessions, org delete): publish/bump the client in the product repo when that product wants those calls. Old apps keep working.

You must not:

• Change AUTH_ISSUER
• Replace private.pem without publishing the new public key under a new kid and keeping the old one until tokens expire (today the code only serves one kid — so do not rotate the PEM in prod until you add multi-kid support)
• Point DNS at a new empty database (all users vanish; old refresh tokens die)

Rollback: keep the previous image tag. Redeploy it. Schema migrations should stay backward-compatible (your SQL is additive).

───

10. Go-live checklist

• [ ] https://auth.plexapps.com/health → 200 ok
• [ ] https://auth.plexapps.com/.well-known/jwks.json → one RSA JWK
• [ ] First admin created with bootstrap token; console login works
• [ ] Bootstrap token removed/rotated; open registration still false
• [ ] CORS lists only real HTTPS app origins
• [ ] AUTH_RATE_LIMIT_TRUST_PROXY=true + cf-connecting-ip
• [ ] Mail reachable or verification temporarily handled and documented
• [ ] OAuth redirect URIs match if enabled
• [ ] Postgres backups on
• [ ] At least one product validates JWTs with this issuer and a grant
• [ ] Cloudflare cache bypassed for this hostname

───

11. Mental model after this

Browser / SPA / other APIs
        │  HTTPS
        ▼
Cloudflare (plexapps zone)  TLS, WAF, optional Tunnel
        │
        ▼
Docker: opendesk-auth :8090
        │
        ▼
Postgres (users, refresh hashes, audit)

Users do not download Auth. You run one service on auth.plexapps.com. New behavior ships when you deploy a new container to that same URL. Product repos only change when they want a new SDK method or a new audience name.
