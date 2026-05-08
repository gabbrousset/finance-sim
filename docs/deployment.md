# deployment

live at `https://finance.gabbrousset.dev` — nginx → Node (adapter-node, :3002) → SQLite at `~/finance-sim/finance.db`.

## how it deploys

```
push to main
  → GitHub Actions (.github/workflows/deploy.yml)
  → ssh gabriel@droplet "finance-sim"   (key restricted via authorized_keys command=)
  → ~/droplet-config/scripts/deploy.sh  (reads $SSH_ORIGINAL_COMMAND)
  → projects/finance-sim/setup.sh       (git pull + pnpm install + build + migrate)
  → sudo systemctl restart finance-sim
```

The deploy key in `DROPLET_SSH_KEY` is a forced-command key — it can only invoke `deploy.sh`. No shell access.

## manual deploy

SSH in and run:

```bash
bash ~/droplet-config/projects/finance-sim/setup.sh
sudo systemctl restart finance-sim
```

Or trigger from GitHub: Actions tab → Deploy → Run workflow.

## logs

Live tail:

```bash
sudo journalctl -u finance-sim -f
```

Last hour:

```bash
journalctl -u finance-sim --since "1h ago"
```

Since last boot:

```bash
journalctl -u finance-sim -b
```

## rollback

**Option 1 — git revert (preferred):** revert the bad commit and push to main. Auto-deploy runs.

**Option 2 — pin a SHA on the droplet:**

```bash
cd ~/finance-sim
git checkout <prev-sha>
bash ~/droplet-config/projects/finance-sim/setup.sh
sudo systemctl restart finance-sim
```

To get back to the tip: `git checkout main && git pull`, then repeat.

## secrets

`.env` lives at `~/finance-sim/.env` on the droplet. Never committed. Populate manually on first deploy (see `.env.example` in the repo root).

| var | purpose |
|-----|---------|
| `DATABASE_URL` | path to SQLite file, default `./finance.db` |
| `RP_ID` | WebAuthn relying-party ID (`finance.gabbrousset.dev`) |
| `ORIGIN` | WebAuthn origin (`https://finance.gabbrousset.dev`) |
| `FINNHUB_API_KEY` | live quote lookups (60 req/min free tier) |
| `TWELVEDATA_API_KEY` | historical EOD data (800 req/day free tier) |
| `PORT` | Node listen port — must match nginx upstream (`3002`) |
| `HOST` | Node listen address — `127.0.0.1` (loopback only) |

## backups

DigitalOcean's weekly automated backups cover the entire droplet, including `~/finance-sim/finance.db`.

Manual snapshot before a risky migration:

```bash
scp gabriel@209.38.1.94:~/finance-sim/finance.db ./backups/finance-$(date +%Y%m%d).db
```

Keep a few recent snapshots locally. The DB file is small — a portfolio with thousands of trades is still under a few MB.

## first-time setup

DNS A record for `finance.gabbrousset.dev` already points to `209.38.1.94` (carried over from v2). Certbot cert already exists.

Steps for the initial Node deploy:

1. SSH into the droplet
2. Populate `~/finance-sim/.env` from `.env.example` with real API keys
3. Trigger a deploy: GitHub Actions → Deploy → "Run workflow" (or push any commit to main)
4. Once the service is running: `sudo systemctl enable finance-sim` (if not already enabled)
5. Verify: `curl -s https://finance.gabbrousset.dev` returns HTML

If migrating from v2 (Flask/uWSGI), stop the old service first:

```bash
sudo systemctl stop finance-sim
sudo systemctl disable finance-sim
```

Then deploy v3 and re-enable.

## stack summary

| layer | detail |
|-------|--------|
| reverse proxy | nginx, TLS terminated by certbot |
| app server | Node 24, `@sveltejs/adapter-node`, port 3002 |
| database | SQLite (better-sqlite3), WAL mode, `~/finance-sim/finance.db` |
| migrations | Drizzle Kit — run by `setup.sh` on each deploy, also applied lazily on first DB use |
| auth | WebAuthn passkeys via `@simplewebauthn/server` |
| market data | Finnhub (live quotes) + TwelveData (historical EOD) |
