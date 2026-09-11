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
COPY package.json package-lock.json* yarn.lock* ./

# Try yarn first, fall back to npm
RUN if [ -f yarn.lock ]; then \
      yarn install --frozen-lockfile --network-timeout 600000; \
    else \
      npm ci --legacy-peer-deps; \
    fi

# Copy source
COPY . ./

# Remove local env files
RUN rm -f .env .env.local .env.development

# Build
RUN npm run build || yarn build

# Verify build succeeded
RUN test -f /app/build/index.html || (echo "BUILD FAILED: No index.html found" && exit 1)

# =========================================
# Stage 2 — Serve with Nginx
# =========================================
FROM nginx:1.27-alpine

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy build output - must exist
COPY --from=builder /app/build /usr/share/nginx/html

# Verify files copied
RUN test -f /usr/share/nginx/html/index.html || (echo "ERROR: index.html not copied" && exit 1)

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
