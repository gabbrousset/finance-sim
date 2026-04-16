# Deployment

Pushing to `main` automatically deploys to `https://finance.gabbrousset.dev` via GitHub Actions.

**Workflow:** work on branches, merge to main when ready to update the live site.

**What happens on push:**
1. GitHub Actions SSHes into the droplet
2. Pulls the latest code and rebuilds
3. Restarts the service

**Manual deploy** (from the droplet):
```bash
~/droplet-config/scripts/deploy.sh finance-sim
```

**Infrastructure config** (nginx, systemd, setup scripts) lives in the [droplet-config](https://github.com/gabbrousset/droplet-config) repo under `projects/finance-sim/`.
