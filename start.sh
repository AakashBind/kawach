#!/bin/sh
python3 -m uvicorn ml.service.app:app --host 127.0.0.1 --port 8000 &
exec node backend/dist/server.js
