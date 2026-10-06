FROM node:20-bookworm-slim AS dependencies
RUN corepack enable && corepack prepare pnpm@8.10.5 --activate
WORKDIR /app
COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY apps/web/package.json apps/web/package.json
RUN pnpm install --frozen-lockfile

FROM node:20-bookworm-slim AS build
RUN corepack enable && corepack prepare pnpm@8.10.5 --activate
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY --from=dependencies /app/apps/web/node_modules ./apps/web/node_modules
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/web ./apps/web
ENV NEXT_TELEMETRY_DISABLED=1 API_INTERNAL_URL=http://free-mcp-report-api:8080
RUN pnpm --dir apps/web build

FROM node:20-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
RUN useradd --system --uid 10001 --create-home observatory
COPY --from=build --chown=observatory:observatory /app/apps/web/.next/standalone ./
COPY --from=build --chown=observatory:observatory /app/apps/web/.next/static ./apps/web/.next/static
COPY --from=build --chown=observatory:observatory /app/apps/web/public ./apps/web/public
USER observatory
EXPOSE 3000
CMD ["node", "apps/web/server.js"]
