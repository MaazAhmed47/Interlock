# ── Dashboard build + static serve ────────────────────────────────────────────
# Used by the offline demo compose stack (demo/offline/docker-compose.yml).
# VITE_INTERLOCK_API_URL is baked at build time — point it at the gateway URL
# the BROWSER will use (http://localhost:8001 for the local demo).
FROM node:20-alpine AS build

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
ARG VITE_INTERLOCK_API_URL=http://localhost:8001
ENV VITE_INTERLOCK_API_URL=${VITE_INTERLOCK_API_URL}
RUN npm run build

FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /build/dist /usr/share/nginx/html
EXPOSE 80
