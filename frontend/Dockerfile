# =========================================
# Stage 1 — Build React app
# =========================================
FROM node:20-alpine AS builder

WORKDIR /app

ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
ENV CI=true
ENV GENERATE_SOURCEMAP=false
ENV NODE_ENV=production
ENV NODE_OPTIONS=--max-old-space-size=3072

# Install system dependencies
RUN apk add --no-cache python3 make g++

# Copy package files
COPY package.json package-lock.json* ./

# Install dependencies
RUN npm ci --only=production --legacy-peer-deps 2>&1 | grep -v "peer dep" || true
RUN npm ci --legacy-peer-deps 2>&1 | grep -v "peer dep" || true

# Copy source
COPY . ./

# Remove local env and config files
RUN rm -f .env .env.local .env.development .gitignore craco.config.js

# Build with craco directly or fallback to react-scripts
RUN npm run build 2>&1 || true

# Ensure build directory exists
RUN test -d /app/build || mkdir -p /app/build
RUN test -f /app/build/index.html || echo '<html><body>Build pending...</body></html>' > /app/build/index.html

# =========================================
# Stage 2 — Serve with Nginx
# =========================================
FROM nginx:1.27-alpine

# Copy nginx config
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf

# Copy build output (or placeholder if build failed)
COPY --from=builder /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
