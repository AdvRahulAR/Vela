# Vela privacy proxy. Build: docker build -t vela-privacy .
# Pin the base images by digest in production (docker buildx imagetools inspect node:22-alpine).

FROM node:22-alpine AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
COPY bin ./bin
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build /src/dist ./dist
COPY --from=build /src/node_modules ./node_modules
COPY package.json README.md LICENSE ./
COPY schemas ./schemas
# Runs as the unprivileged "node" user and writes nothing to disk: audit events
# go to stdout (--audit-stdout) for the log collector, or to a mounted volume.
USER node
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8787/health >/dev/null || exit 1
ENTRYPOINT ["node", "dist/bin/vela-cli.js", "proxy", "--host", "0.0.0.0", "--port", "8787"]
# Client tokens are required on a non-loopback host: mount them at /etc/vela/tokens.
CMD ["--auth-token-file", "/etc/vela/tokens", "--audit-stdout", "--policy", "dpdp-baseline"]
