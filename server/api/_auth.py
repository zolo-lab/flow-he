import hmac
import json
import os


def users():
    """{token: name}. FLOWHE_TOKEN = הבעלים; FLOWHE_USERS = "שם:טוקן;שם2:טוקן2" — קוד הפעלה אישי לכל חבר
    (אפשר לבטל אחד בלי לגעת באחרים, ואף אחד מהם לא רואה את המפתחות של RunPod/Claude)."""
    out = {}
    own = os.environ.get("FLOWHE_TOKEN", "")
    if own:
        out[own] = "owner"
    # FLOWHE_WEB_USERS: קודים לדפי אינטרנט (למשל אפליקציית הגיבוש). אותו פורמט; נפרד כדי שאפשר לבטל בלי לגעת בקודים של האפליקציה
    raw = os.environ.get("FLOWHE_USERS", "") + ";" + os.environ.get("FLOWHE_WEB_USERS", "")
    for part in raw.replace(",", ";").split(";"):
        if ":" in part:
            name, tok = part.split(":", 1)
            if tok.strip():
                out[tok.strip()] = name.strip()
    return out


def check(handler):
    """Bearer token. מחזיר את שם המשתמש אם תקין (ונרשם ללוג של Vercel), אחרת שולח 401 ומחזיר None."""
    got = handler.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    for tok, name in users().items():
        if got and hmac.compare_digest(tok, got):
            print(f"user={name} path={handler.path}", flush=True)
            return name
    send(handler, 401, {"error": "unauthorized"})
    return None


def _cors(handler):
    """CORS רק לאתרים שב-FLOWHE_CORS_ORIGINS (רשימה מופרדת בפסיקים). בלי המשתנה — אין CORS, כמו קודם."""
    origin = handler.headers.get("Origin", "")
    allowed = [o.strip().rstrip("/") for o in os.environ.get("FLOWHE_CORS_ORIGINS", "").split(",") if o.strip()]
    if origin and origin.rstrip("/") in allowed:
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
        return True
    return False


def preflight(handler):
    """OPTIONS מהדפדפן לפני POST עם Authorization."""
    handler.send_response(204)
    if _cors(handler):
        handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        handler.send_header("Access-Control-Max-Age", "600")
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def send(handler, code, obj):
    body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    handler.send_response(code)
    _cors(handler)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def body(handler):
    n = int(handler.headers.get("Content-Length") or 0)
    return json.loads(handler.rfile.read(n) or b"{}")
