# ScamShield X Hybrid AI Backend (Flat-root deployment)

This package is specifically structured for a GitHub repository where files are uploaded at the repository root. Deploy with Render Blueprint using render.yaml.

- FastAPI entrypoint: `main:app`
- ML training: `python ml/train_text.py --data data/text_training.csv` and `python ml/train_url.py --data data/url_training.csv`
- Copy templates to the filenames above and populate them with properly licensed, de-identified labeled data. Templates alone are not a trained model.
- Configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in Render. Configure OPENAI_API_KEY only if using cloud AI. Set a strong API_KEY and configure frontend with that key securely through an appropriate proxy; do not expose service-role keys in browser code.
- Apply `supabase/schema.sql` in Supabase SQL Editor.
