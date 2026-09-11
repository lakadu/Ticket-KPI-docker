# =========================================
# Stage 1 — Build React app with npm
# =========================================
FROM node:20-alpine AS builder

WORKDIR /app

ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
ENV CI=false

# Install deps (npm by default)
COPY package.json package-lock.json* ./
RUN npm install --legacy-peer-deps

# Copy source
COPY . ./

# Remove local env files
RUN rm -f .env .env.local .env.development

# Build production bundle
RUN npm run build

# =========================================
# Stage 2 — Serve with Nginx + reverse proxy /api
# =========================================
FROM nginx:1.27-alpine

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build output to document root
COPY --from=builder /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
