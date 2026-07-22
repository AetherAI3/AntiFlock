# syntax=docker/dockerfile:1.7
FROM node:24.12.0-bookworm-slim AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY . .
RUN npm run build

FROM node:24.12.0-bookworm-slim AS runtime

ENV NODE_ENV=production \
    HOSTNAME=0.0.0.0 \
    PORT=4173
WORKDIR /app
COPY --chown=node:node --from=build /app/dist/standalone/ ./
USER node
EXPOSE 4173
CMD ["node", "server.js"]
