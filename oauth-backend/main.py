import os
import hmac
import json
import secrets
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from google_auth_oauthlib.flow import Flow

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

SCOPES = [
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",

    # Gmail — full mailbox access
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.settings.basic",

    # Google Calendar — full management
    "https://www.googleapis.com/auth/calendar",

    # Google Drive — full file management
    "https://www.googleapis.com/auth/drive",

    # Google Contacts — full contact management
    "https://www.googleapis.com/auth/contacts",

    # Google Tasks — full task management
    "https://www.googleapis.com/auth/tasks",

    # YouTube — account and content management
    "https://www.googleapis.com/auth/youtube",
    "https://www.googleapis.com/auth/youtube.force-ssl",
    "https://www.googleapis.com/auth/youtube.upload",
]

TOKEN_PATH = Path(
    os.getenv("TOKEN_PATH", ".local/google-token.json")
)

if not TOKEN_PATH.is_absolute():
    TOKEN_PATH = BASE_DIR / TOKEN_PATH

app = FastAPI(title="NEXA Google OAuth Backend")


def create_oauth_flow():
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")

    if not all([client_id, client_secret, redirect_uri]):
        raise RuntimeError("Google OAuth environment variables are missing.")

    client_config = {
        "web": {
            "client_id": client_id,
            "client_secret": client_secret,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [redirect_uri],
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
    )
    flow.redirect_uri = redirect_uri

    return flow


def save_credentials(credentials):
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)

    temporary_file = TOKEN_PATH.with_suffix(".tmp")
    temporary_file.write_text(
        credentials.to_json(),
        encoding="utf-8",
    )

    try:
        os.chmod(temporary_file, 0o600)
    except OSError:
        pass

    temporary_file.replace(TOKEN_PATH)


@app.get("/")
def home():
    return {
        "service": "NEXA Google OAuth Backend",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/oauth/google/start")
def google_auth_start():
    try:
        flow = create_oauth_flow()

        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
        )

        response = RedirectResponse(authorization_url)

        response.set_cookie(
            "nexa_oauth_state",
            state,
            httponly=True,
            secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
            samesite="lax",
            max_age=600,
            path="/oauth/google",
        )

        return response

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "OAuth initialization failed."},
        )


@app.get("/oauth/google/callback")
def google_auth_callback(request: Request, code: str = "", state: str = ""):
    saved_state = request.cookies.get("nexa_oauth_state")

    response = JSONResponse({"error": "OAuth authorization failed."})

    response.delete_cookie(
        "nexa_oauth_state",
        path="/oauth/google",
    )

    if not saved_state or not state or not hmac.compare_digest(
        saved_state, state
    ):
        response.status_code = 400
        response.body = json.dumps(
            {"error": "Invalid OAuth state."}
        ).encode()
        return response

    if not code:
        response.status_code = 400
        response.body = json.dumps(
            {"error": "Authorization code missing."}
        ).encode()
        return response

    try:
        flow = create_oauth_flow()
        flow.fetch_token(code=code)

        credentials = flow.credentials
        save_credentials(credentials)

        return JSONResponse({
            "success": True,
            "message": "Google authorization completed.",
            "scopes": credentials.scopes,
            "refresh_token_received": bool(credentials.refresh_token),
            "next_step": "Google MCP integration",
        })

    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Token exchange or storage failed."},
        )


@app.get("/oauth/google/status")
def google_auth_status():
    if not TOKEN_PATH.exists():
        return {"authorized": False}

    try:
        token_data = json.loads(
            TOKEN_PATH.read_text(encoding="utf-8")
        )

        return {
            "authorized": True,
            "scopes": token_data.get("scopes", []),
            "expiry": token_data.get("expiry"),
        }

    except (OSError, ValueError):
        return JSONResponse(
            status_code=500,
            content={"error": "Unable to read authorization status."},
        )
