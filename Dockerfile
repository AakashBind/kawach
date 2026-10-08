# ==============================================================================
# Scam-Shield Production Dockerfile for Railway.app
# Unified Multi-Service Container: Python ML (FastAPI) + Node.js (Express) + React (SPA)
# ==============================================================================

# ------------------------------------------------------------------------------
# Stage 1: Build Frontend SPA
# ------------------------------------------------------------------------------
FROM node:20-slim AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci || npm install

COPY frontend ./
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 2: Build Backend TypeScript
# ------------------------------------------------------------------------------
FROM node:20-slim AS backend-builder
WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm ci || npm install

COPY backend ./
RUN npm run build

# ------------------------------------------------------------------------------
# Stage 3: Unified Production Runtime (Python 3.11 + Node.js 20 LTS)
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS runner

# Install Node.js 20, build dependencies (for SQLite native addon), and OpenMP (for XGBoost)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    build-essential \
    python3-dev \
    libgomp1 \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Install Python ML requirements
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# 2. Setup backend production dependencies
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install --omit=dev || npm ci --omit=dev

# 3. Copy compiled backend dist and runtime files
COPY --from=backend-builder /app/backend/dist ./dist
COPY backend/src/database/schema.sql ./src/database/schema.sql

# 4. Copy compiled frontend build
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist

# 5. Copy ML microservice code and pre-trained models
WORKDIR /app
COPY ml ./ml

# 6. Environment variables for Railway
ENV NODE_ENV=production
ENV PORT=8080
ENV ML_SERVICE_URL=http://127.0.0.1:8000
ENV DATABASE_PATH=/app/data/scam_shield.db

# Expose Railway default ports
EXPOSE 8080 5000

# Start both ML microservice in background and Node.js backend in foreground
CMD ["sh", "-c", "python3 -m uvicorn ml.service.app:app --host 127.0.0.1 --port 8000 & node backend/dist/server.js"]
