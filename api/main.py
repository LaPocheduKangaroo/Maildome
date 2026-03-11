"""
api/main.py — MailDome API entry point
"""
import os
import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI

app = FastAPI(
    title="MailDome",
    description="Email security pipeline API",
    version="0.1.0"
)

@app.get("/")
async def root():
    return {"status": "ok", "service": "MailDome"}

@app.get("/api/v1/status")
async def status():
    components = {"api": "ok"}

    # Check PostgreSQL
    try:
        conn = await asyncpg.connect(
            host="postgres",
            port=5432,
            user=os.environ.get("POSTGRES_USER", "maildome"),
            password=os.environ.get("POSTGRES_PASSWORD", ""),
            database=os.environ.get("POSTGRES_DB", "maildome"),
        )
        await conn.execute("SELECT 1")
        await conn.close()
        components["postgres"] = "ok"
    except Exception as e:
        components["postgres"] = f"error: {e}"

    # Check Redis
    try:
        r = aioredis.from_url(
            f"redis://:{os.environ.get('REDIS_PASSWORD', '')}@redis:6379"
        )
        await r.ping()
        await r.aclose()
        components["redis"] = "ok"
    except Exception as e:
        components["redis"] = f"error: {e}"

    overall = "ok" if all(v == "ok" for v in components.values()) else "degraded"

    return {
        "status": overall,
        "version": "0.1.0",
        "components": components
    }
