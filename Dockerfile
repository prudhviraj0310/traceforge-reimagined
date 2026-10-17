# Multi-stage Dockerfile for Render Web Service deployment
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# Build with node-server preset
ENV NITRO_PRESET=node-server
RUN npm run build

# Production Runner
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000
ENV NITRO_PRESET=node-server

COPY package*.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/.output ./.output
COPY --from=builder /app/render-start.mjs ./render-start.mjs

EXPOSE 3000

CMD ["node", "render-start.mjs"]
