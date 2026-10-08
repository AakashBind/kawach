#!/bin/sh
set -e

echo "=========================================================="
echo " Starting Kawach Production Platform on Railway"
echo "=========================================================="

export PORT="${PORT:-8080}"
export NODE_ENV="${NODE_ENV:-production}"
export ML_SERVICE_URL="${ML_SERVICE_URL:-http://127.0.0.1:8000}"
export DATABASE_PATH="${DATABASE_PATH:-/app/data/scam_shield.db}"

# Ensure database directory exists
mkdir -p "$(dirname "$DATABASE_PATH")"

echo "[1/2] Starting Python ML Microservice on 127.0.0.1:8000..."
python3 -m uvicorn ml.service.app:app --host 127.0.0.1 --port 8000 &
ML_PID=$!

# Wait for ML service to become healthy (up to 25 seconds)
echo "Waiting for ML Service to load models and verify artifacts..."
for i in $(seq 1 25); do
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        echo "ML Microservice is ready!"
        break
    fi
    sleep 1
done

echo "[2/2] Starting Node.js Backend API & SPA on port $PORT..."
exec node backend/dist/server.js
