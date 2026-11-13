import secrets
from fastapi import Header, HTTPException
from config import API_KEY

async def verify_api_key(x_api_key: str | None = Header(default=None)):
    # Local development may leave API_KEY blank. Set a strong key in production.
    if API_KEY and (not x_api_key or not secrets.compare_digest(x_api_key, API_KEY)):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
