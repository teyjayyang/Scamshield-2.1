import re
from urllib.parse import urlparse
import numpy as np

def url_features(raw: str) -> dict:
    value = raw.strip()
    candidate = value if "://" in value else "https://" + value
    try:
        p = urlparse(candidate)
        host = (p.hostname or "").lower()
        path = p.path or ""
        labels = host.split(".") if host else []
        ip = bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host))
        return {
            "https": int(p.scheme == "https"),
            "host_length": len(host),
            "url_length": len(value),
            "dot_count": host.count("."),
            "hyphen_count": host.count("-"),
            "digit_count": sum(c.isdigit() for c in host),
            "subdomain_count": max(0, len(labels)-2),
            "has_ip": int(ip),
            "has_at": int("@" in value),
            "has_punycode": int("xn--" in host),
            "has_port": int(p.port is not None) if p.port else 0,
            "has_login_word": int(bool(re.search(r"login|verify|secure|account|bank|wallet|signin", value, re.I))),
            "has_redirect_word": int(bool(re.search(r"redirect|return|continue|next=", value, re.I))),
            "path_depth": len([x for x in path.split("/") if x]),
            "query_length": len(p.query),
        }
    except Exception:
        return {"https":0,"host_length":0,"url_length":len(value),"dot_count":0,"hyphen_count":0,
                "digit_count":0,"subdomain_count":0,"has_ip":0,"has_at":int("@" in value),
                "has_punycode":0,"has_port":0,"has_login_word":0,"has_redirect_word":0,
                "path_depth":0,"query_length":0}

URL_FEATURE_COLUMNS = list(url_features("https://example.com").keys())

def url_feature_vector(url: str):
    f = url_features(url)
    return np.array([[f[k] for k in URL_FEATURE_COLUMNS]], dtype=float)
