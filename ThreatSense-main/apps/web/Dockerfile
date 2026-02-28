# apps/web/Dockerfile
# Next.js production multi-stage build

FROM node:20-alpine AS deps
WORKDIR /app

# Install deps based on lockfile (supports npm/yarn/pnpm)
COPY package.json ./
COPY package-lock.json* yarn.lock* pnpm-lock.yaml* ./

RUN \
  if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm i --frozen-lockfile; \
  elif [ -f yarn.lock ]; then yarn install --frozen-lockfile; \
  elif [ -f package-lock.json ]; then npm ci; \
  else npm install; \
  fi

FROM node:20-alpine AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build Next.js
RUN \
  if [ -f pnpm-lock.yaml ]; then corepack enable && pnpm run build; \
  elif [ -f yarn.lock ]; then yarn build; \
  else npm run build; \
  fi

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# If you use Next's standalone output, this is best.
# It works if next.config.js has: output: "standalone"
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000
CMD ["node", "server.js"]
