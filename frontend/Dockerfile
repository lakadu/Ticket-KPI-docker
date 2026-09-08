# =========================================
# Stage 1 — Build React app dengan CRACO
# =========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Aktifkan corepack untuk pin yarn v1 sesuai package.json
RUN corepack enable

# ARG dari docker-compose (untuk build-time env var)
ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
ENV CI=false

# Install deps dulu untuk layer caching
COPY package.json yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 600000

# Copy source
COPY . ./

# Hapus .env lokal supaya URL preview emergent tidak ikut
RUN rm -f .env .env.local .env.development

# Build production bundle
RUN yarn build

# =========================================
# Stage 2 — Serve dengan Nginx + reverse proxy /api
# =========================================
FROM nginx:1.27-alpine

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy hasil build ke document root
COPY --from=builder /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
