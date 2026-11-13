import os
from dotenv import load_dotenv
load_dotenv()

def get(name, default=""):
    return os.getenv(name, default)

APP_NAME = get("APP_NAME", "ScamShield X ML API")
API_KEY = get("API_KEY")
SUPABASE_URL = get("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = get("SUPABASE_SERVICE_ROLE_KEY")
SUPABASE_STORAGE_BUCKET = get("SUPABASE_STORAGE_BUCKET", "scam-evidence")
OPENAI_API_KEY = get("OPENAI_API_KEY")
OPENAI_VISION_MODEL = get("OPENAI_VISION_MODEL", "gpt-4o-mini")
MAX_UPLOAD_MB = int(get("MAX_UPLOAD_MB", "8"))
ALLOW_ORIGINS = [x.strip() for x in get("ALLOW_ORIGINS", "https://incomparable-kangaroo-0209c3.netlify.app,https://6af693f1acd5d9a6525b7689--incomparable-kangaroo-0209c3.netlify.app").split(",") if x.strip()]
STORE_RAW_EVIDENCE = get("STORE_RAW_EVIDENCE", "false").lower() == "true"
