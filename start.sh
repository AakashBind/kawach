#!/bin/sh
set -e

echo "=========================================================="
echo " Starting Scam-Shield Production Platform on Railway"
echo "=========================================================="

export PORT="${PORT:-5000}"
export NODE_ENV="${NODE_ENV:-production}"
export ML_SERVICE_URL="${ML_SERVICE_URL:-http://127.0.0.1:8000}"
export DATABASE_PATH="${DATABASE_PATH:-/app/data/scam_shield.db}"

# Ensure data directory exists for SQLite database
mkdir -p "$(dirname "$DATABASE_PATH")"

echo "[1/2] Starting Python ML Microservice (FastAPI + XGBoost)..."
python3 -m uvicorn ml.service.app:app --host 127.0.0.1 --port 8000 &
ML_PID=$!

# Trap termination signals to shut down child processes cleanly
cleanup() {
    echo "Stopping background processes..."
    kill -TERM "$ML_PID" 2>/dev/null || true
    wait "$ML_PID" 2>/dev/null || true
    exit 0
}
trap cleanup SIGTERM SIGINT

# Wait for ML service to become healthy (maximum 20 seconds)
echo "Waiting for ML Service to load models and verify artifacts..."
for i in $(seq 1 20); do
    if curl -s http://127.0.0.1:8000/health > /dev/null 2>&1; then
        echo "ML Microservice is ready!"
        break
    fi
    sleep 1
done

echo "[2/2] Starting Node.js Backend API on port $PORT..."
node backend/dist/server.js &
NODE_PID=$!

# Wait for either process to terminate
wait -n "$ML_PID" "$NODE_PID"
EXIT_CODE=$?

cleanup
exit $EXIT_CODE
