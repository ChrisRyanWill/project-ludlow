# Running your own server

*This is for someone who will run Project Ludlow for **one** union campaign or workspace. Read the [threat model](THREAT_MODEL.md) first. The software is an early prototype, has not had an independent security audit, and its legal texts are drafts that need a labor attorney. The project does not run a public instance, and does not recommend running one for strangers.*

## 1. Decide who runs it

- **Not a trustee.** The release lock (the number of signed cards before anyone can get the sealed cards) is enforced by the server. If a trustee controls the server, the lock binds nothing.
- **Not the employer's IT**, and not an account the employer can reach.
- **Someone the committee trusts, who will be around.** A labor-friendly technologist, a sympathetic union's IT, or a small paid host under a personal account.

Write down who holds what: the server login, the master key and the backups. Keep those three apart where you can.

## 2. What you need

- **A small Linux server** with a public address. One CPU and 1 GB of memory are enough; the database is one SQLite file.
- **A domain name, with HTTPS in front** of the app. The steps below use Caddy, which obtains certificates by itself. nginx works too.
- **Docker**, or Node 20 or later if you run it without Docker.
- **For real confirmation emails:** a Postmark account (server token, a verified sender address) and an inbox someone reads for replies. In the US pack, the confirmation email is how a signer gets a copy of their card, as NLRB General Counsel memo GC 15-08 calls for. Without an email provider, `EMAIL_PROVIDER=dev` keeps the messages in memory only, and **nobody receives them**.

## 3. Generate the master key, and keep it

The workspace (the union once it is public) encrypts personal fields with a key made from `WORKSPACE_MASTER_KEY`.

```bash
openssl rand -base64 32
```

- **Store it in a password manager** or secret store, and **separately from database backups**. A backup and the key together reveal members' names and contact details; either alone does not.
- **If it is lost, the workspace's encrypted fields cannot be read again.** There is no recovery.
- The server refuses to start without it when `NODE_ENV=production`, or when it listens on any address other than this machine.

## 4. Run it with Docker

```bash
git clone https://github.com/ChrisRyanWill/project-ludlow.git && cd project-ludlow
docker build -t project-ludlow .
docker run -d --name ludlow --restart unless-stopped \
  -p 127.0.0.1:8787:8787 -v ludlow-data:/data \
  -e APP_BASE_URL=https://union.example.org \
  -e WORKSPACE_MASTER_KEY='(the key from step 3)' \
  -e TRUST_PROXY=1 \
  -e EMAIL_PROVIDER=postmark -e POSTMARK_SERVER_TOKEN='(token)' \
  -e EMAIL_FROM=cards@union.example.org -e CONFIRMATION_REPLY_TO=committee@union.example.org \
  project-ludlow
```

- **Defaults in the image:** it already sets `NODE_ENV=production`, `DATABASE_PATH=/data/ludlow.db`, `PORT=8787` and `HOST=0.0.0.0`. It runs as an unprivileged user and has a health check.
- **`-p 127.0.0.1:8787:8787`** publishes the port on this machine only, so the app is reachable only through the HTTPS proxy.
- **`TRUST_PROXY`** is the number of reverse proxies in front: `1` for Caddy on the same machine. It must be a whole number. Only `X-Forwarded-For` is read, counted from the end.
- **Keep the key out of your shell history:** pass it through a file (`--env-file`, with permissions 600) instead of typing it on the command line.

Every setting is listed in the README's [Configuration](../README.md#configuration) table.

## 5. HTTPS in front (Caddy)

`/etc/caddy/Caddyfile`:

```
union.example.org {
    reverse_proxy 127.0.0.1:8787
    log {
        output discard
    }
}
```

- **Access logs are discarded here on purpose.** The app itself logs only the method, route pattern, status, duration and time: no addresses, no paths with ids, no bodies. A proxy that logs full URLs and addresses would undo that.
- **nginx:** turn `access_log` off for this site, and set `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`.

The app sends its own strict security headers (CSP, HSTS, no referrer). Do not add scripts, analytics or fonts through the proxy.

## 6. Check it

1. **Open `https://union.example.org/verify`.** It shows the SHA-256 of the app's code. Build the same commit on another computer (`npm ci && npm run build`) and compare the printed hash; they should match. The page says what this check cannot catch.
2. **Start a test campaign** with a throwaway name. Sign one card to your own address and check the confirmation email arrives. Then destroy the campaign (it needs the trustees).
3. **Try one thing that should fail:** open `https://union.example.org/api/campaigns/x/export-bundle` without signing in. It must be refused.

## 7. Back it up

- **What to back up:** the Docker volume (`ludlow-data`), which holds `ludlow.db`. A consistent copy while the server runs:

  ```bash
  docker exec ludlow node -e "require('better-sqlite3')('/data/ludlow.db').backup('/data/backup.db').then(()=>console.log('ok'))"
  docker cp ludlow:/data/backup.db ./ludlow-$(date +%F).db
  ```

- **Encrypt backups before they leave the server**, for example with `age` or `gpg`. Keep them away from the master key.
- **What a stolen backup would show:**
  - Campaign data is ciphertext the server cannot read, but a copy still shows counts, times and who invited whom.
  - The workspace's personal fields need the master key.
  - The threat model lists exactly what a copy shows.
- **Idle campaigns are deleted on their own** after `CAMPAIGN_INACTIVITY_DAYS` (180 by default). Old backups keep them. Delete backups you no longer need.

## 8. Update it

```bash
git pull && docker build -t project-ludlow . && docker stop ludlow && docker rm ludlow
# then the same docker run command as in step 4
```

- **Migrations:** schema changes for existing databases run automatically at start. Back up first.
- **After updating,** check `/verify` again and tell the trustees the new fingerprint, so they can compare it before opening cards.

## 9. Keep in mind

- **Run one instance.** Sign-in challenges and rate limits are kept in memory.
- **Do not set `RATE_LIMIT_DISABLED`** on a real server. It is for tests.
- **Leave `ONLINE_OFFICER_ELECTIONS` off** until an attorney has approved online officer elections for your union.
- **If something goes wrong,** report security problems privately as described in [SECURITY.md](../SECURITY.md). Trustees can pause signing at once from their dashboard.
