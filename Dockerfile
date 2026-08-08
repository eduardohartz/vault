# Multi-stage: build tooling and dev dependencies stay out of the final image.
FROM node:22.21.1-trixie-slim AS deps

WORKDIR /usr/src/app

# Corepack pins pnpm to the exact version in package.json's packageManager
# field, so the image cannot drift to a different resolver than local or CI.
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# The postinstall hook regenerates the Prisma client; it must exist before
# install runs. It no-ops here because prisma/ is not copied until later.
COPY scripts/postinstall.mjs ./scripts/postinstall.mjs
# --frozen-lockfile fails if the lockfile is stale rather than silently
# resolving something newer, which is what the old `npm install
# --frozen-lockfile` did (that flag is yarn/pnpm syntax; npm ignored it).
RUN pnpm install --frozen-lockfile

COPY prisma ./prisma
COPY prisma.config.ts ./prisma.config.ts
RUN pnpm exec prisma generate


FROM node:22.21.1-trixie-slim AS builder

WORKDIR /usr/src/app

# Commit being built. Pins Next's build ID so the same source yields the same
# asset paths, which is what makes the deployment comparable to what CI built.
ARG BUILD_SHA=development
ARG BUILD_TIMESTAMP=""
ENV BUILD_SHA=$BUILD_SHA
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

# pnpm's node_modules is a tree of symlinks into node_modules/.pnpm, so the
# whole directory has to move together for the links to resolve.
COPY --from=deps /usr/src/app/node_modules ./node_modules
COPY . .
RUN pnpm exec prisma generate && pnpm run build

# Hash every client asset this build emitted. CI extracts this and the
# integrity monitor compares a live deployment against it.
RUN node scripts/generate-bundle-manifest.mjs --next-dir .next --out /usr/src/app/bundle-manifest.json


# Migrations run from their own image, holding nothing but the Prisma CLI.
#
# Two things this avoids. Hand-picking Prisma's directories into the slim
# runtime image breaks on every upgrade, because the CLI pulls a moving set of
# transitive packages (@prisma/config, jiti, ...). Copying the whole resolved
# tree instead works, but produced a 1.6 GB image to run one migration — it
# dragged in Next, React and every dev tool. So: a clean install of just the
# CLI, at the version read back out of the resolved tree rather than written
# literally here, so the migrator and the generated client cannot drift apart.
# Keeping the CLI out of the app image is a bonus.
FROM node:22.21.1-trixie-slim AS migrator-deps

ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable

COPY --from=deps /usr/src/app/node_modules /tmp/resolved
COPY package.json /tmp/root-package.json

# Both versions are read from the real project rather than written literally:
# the pnpm version from packageManager, and Prisma's from the resolved tree.
# A hardcoded pnpm version here silently went stale the moment package.json
# moved, and an unpinned one falls back to whatever corepack defaults to —
# which is a different pnpm than the rest of the build uses.
RUN mkdir -p /migrator && cd /migrator \
  && node -e 'const fs=require("fs");fs.writeFileSync("package.json",JSON.stringify({name:"vault-migrator",private:true,packageManager:require("/tmp/root-package.json").packageManager}))' \
  && printf 'onlyBuiltDependencies:\n  - prisma\n  - "@prisma/engines"\n' > pnpm-workspace.yaml \
  && pnpm add "prisma@$(node -p "require('/tmp/resolved/prisma/package.json').version")"


FROM node:22.21.1-trixie-slim AS migrator

WORKDIR /usr/src/app

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=migrator-deps /migrator/node_modules ./node_modules
COPY prisma ./prisma
COPY prisma.config.ts ./prisma.config.ts
COPY package.json ./package.json

# Invoked through node rather than the .bin shim: under pnpm that shim is a
# symlink into .pnpm, and the CLI resolves its WASM relative to its own path.
CMD ["node", "./node_modules/prisma/build/index.js", "migrate", "deploy"]


FROM node:22.21.1-trixie-slim AS runner

WORKDIR /usr/src/app

ARG BUILD_SHA=development
ARG BUILD_TIMESTAMP=""

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV BUILD_SHA=$BUILD_SHA
ENV BUILD_TIMESTAMP=$BUILD_TIMESTAMP

# Prisma's query engine needs OpenSSL at runtime.
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# The image previously ran everything as root.
RUN groupadd --system --gid 1001 nodejs \
  && useradd --system --uid 1001 --gid nodejs vault

COPY --from=builder /usr/src/app/public ./public
COPY --from=builder --chown=vault:nodejs /usr/src/app/.next/standalone ./
COPY --from=builder --chown=vault:nodejs /usr/src/app/.next/static ./.next/static

# Kept out of public/ deliberately: the manifest must reach the monitor from
# CI, not from the server being audited. A server vouching for itself proves
# nothing. It lives here only so `docker cp` can retrieve it.
COPY --from=builder /usr/src/app/bundle-manifest.json ./bundle-manifest.json

COPY --chown=vault:nodejs entrypoint.sh ./entrypoint.sh
RUN chmod +x ./entrypoint.sh

# Encrypted blobs live here; create it up front so it is owned by the app user.
RUN mkdir -p /usr/src/app/encrypted_files && chown -R vault:nodejs /usr/src/app/encrypted_files

USER vault

EXPOSE 3000

ENTRYPOINT ["./entrypoint.sh"]
