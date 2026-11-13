from supabase import create_client
from config import SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_STORAGE_BUCKET
_client = None

def client():
    global _client
    if _client is None and SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    return _client

def save_analysis(record: dict):
    c = client()
    if not c:
        return None
    try:
        result = c.table("analyses").insert(record).execute()
        return result.data[0] if result.data else None
    except Exception:
        return None

def upload_evidence(filename: str, content: bytes, content_type: str):
    c = client()
    if not c:
        return None
    try:
        import uuid
        path = f"evidence/{uuid.uuid4().hex}_{filename}"
        c.storage.from_(SUPABASE_STORAGE_BUCKET).upload(path, content, {"content-type":content_type, "upsert":"false"})
        return path
    except Exception:
        return None
