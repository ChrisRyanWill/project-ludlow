# Project Ludlow: one small image, one SQLite file. Mount /data as a volume.
#   docker build -t project-ludlow .
#   docker run -p 8787:8787 -v ludlow-data:/data \
#     -e NODE_ENV=production -e HOST=0.0.0.0 -e APP_BASE_URL=https://your.domain \
#     -e WORKSPACE_MASTER_KEY=$(openssl rand -base64 32) -e TRUST_PROXY=1 \
#     -e EMAIL_PROVIDER=postmark -e POSTMARK_SERVER_TOKEN=... -e EMAIL_FROM=... -e CONFIRMATION_REPLY_TO=... \
#     project-ludlow
# KEEP the master key somewhere safe: without it the workspace's encrypted fields cannot be read.
FROM node:20-slim AS build
WORKDIR /app
# better-sqlite3 has no prebuilt binary for every Node release, so the build stage carries a compiler.
# The runtime image below stays slim: it only receives the compiled result.
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ && rm -rf /var/lib/apt/lists/*
COPY package*.json ./
RUN npm ci
COPY . .
RUN node scripts/build.js && npm prune --omit=dev

FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production DATABASE_PATH=/data/ludlow.db PORT=8787 HOST=0.0.0.0
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/server ./server
COPY --from=build /app/shared ./shared
COPY --from=build /app/web/dist ./web/dist
COPY --from=build /app/package.json ./
# /data must exist and belong to the unprivileged user BEFORE it becomes a volume, or SQLite cannot create its file.
RUN mkdir -p /data && chown node:node /data
VOLUME /data
EXPOSE 8787
USER node
CMD ["node", "server/index.js"]
