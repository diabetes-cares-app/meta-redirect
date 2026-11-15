import os
import secrets
from datetime import datetime, timedelta, timezone
import httpx
import psycopg2
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()

META_APP_ID = os.getenv("META_APP_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
DATABASE_URL = os.getenv("DATABASE_URL")
GRAPH_API_VERSION = "v21.0"


def get_db_connection():
    return psycopg2.connect(DATABASE_URL)


@app.on_event("startup")
def init_db():
    """Creates the table automatically if it doesn't exist yet."""
    if not DATABASE_URL:
        return
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS meta_tokens (
            id SERIAL PRIMARY KEY,
            access_token TEXT NOT NULL,
            expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()


@app.get("/")
async def home():
    return {"status": "Meta OAuth Server Running", "login_url": "/auth/meta/login"}


@app.get("/auth/meta/login")
async def meta_login():
    state = secrets.token_urlsafe(32)
    scopes = "public_profile,email"

    meta_auth_url = (
        f"https://facebook.com{GRAPH_API_VERSION}/dialog/oauth"
        f"?client_id={META_APP_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&state={state}"
        f"&scope={scopes}"
    )

    response = RedirectResponse(url=meta_auth_url)
    response.set_cookie(
        key="oauth_state",
        value=state,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=600,
    )
    return response


@app.get("/auth/meta/callback")
async def meta_callback(request: Request):
    code = request.query_params.get("code")
    returned_state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_reason = request.query_params.get("error_reason")

    if error:
        return HTMLResponse(
            content=f"<h3>Authorization Failed</h3><p>Reason: {error_reason}</p>",
            status_code=400,
        )

    saved_state = request.cookies.get("oauth_state")
    if not saved_state or not returned_state or not secrets.compare_digest(saved_state, returned_state):
        raise HTTPException(status_code=403, detail="Invalid OAuth state parameter.")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code.")

    token_url = f"https://facebook.com{GRAPH_API_VERSION}/oauth/access_token"

    async with httpx.AsyncClient() as client:
        # 1. Get short-lived token
        short_res = await client.get(
            token_url,
            params={
                "client_id": META_APP_ID,
                "redirect_uri": REDIRECT_URI,
                "client_secret": META_APP_SECRET,
                "code": code,
            },
        )
        short_data = short_res.json()
        if "error" in short_data:
            return HTMLResponse(content=f"<pre>{short_data}</pre>", status_code=400)

        # 2. Exchange for 60-day long-lived token
        long_res = await client.get(
            token_url,
            params={
                "grant_type": "fb_exchange_token",
                "client_id": META_APP_ID,
                "client_secret": META_APP_SECRET,
                "fb_exchange_token": short_data.get("access_token"),
            },
        )
        long_data = long_res.json()
        if "error" in long_data:
            return HTMLResponse(content=f"<pre>{long_data}</pre>", status_code=400)

    long_lived_token = long_data.get("access_token")
    expires_in = int(long_data.get("expires_in", 5184000))  # Default 60 days in seconds
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)

    # 3. Save to PostgreSQL
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO meta_tokens (access_token, expires_at) VALUES (%s, %s);",
        (long_lived_token, expires_at),
    )
    conn.commit()
    cur.close()
    conn.close()

    response = HTMLResponse(
        content="""
        <html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h2>Meta Account Connected!</h2>
                <p>Your 60-day token has been saved to the database.</p>
            </body>
        </html>
        """
    )
    response.delete_cookie("oauth_state")
    return response
