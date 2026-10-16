set -a; . ./.env; set +a
exec .venv/Scripts/python -m uvicorn app.main:app --port 8000
