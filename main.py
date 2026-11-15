import os
import secrets
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()

META_APP_ID = os.getenv("META_APP_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")  # e.g., https://railway.app
GRAPH_API_VERSION = "v21.0"


@app.get("/")
async def home():
    return {
        "status": "Meta OAuth Server Running",
        "login_url": "/auth/meta/login"
    }


@app.get("/auth/meta/login")
async def meta_login():
    """
    Step 1: Generates a secure CSRF state token, stores it in an HttpOnly cookie,
    and redirects the user to Meta's OAuth consent screen.
    """
    state = secrets.token_urlsafe(32)

    # Adjust scopes depending on your Meta product (e.g., pages_show_list, instagram_basic)
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
        secure=True,      # Requires HTTPS (Railway provides HTTPS automatically)
        samesite="lax",
        max_age=600       # Expires in 10 minutes
    )
    return response


@app.get("/auth/meta/callback")
async def meta_callback(request: Request):
    """
    Step 2: Validates the state parameter, exchanges the code for a short-lived token,
    and immediately upgrades it to a 60-day long-lived token.
    """
    code = request.query_params.get("code")
    returned_state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_reason = request.query_params.get("error_reason")

    if error:
        return HTMLResponse(
            content=f"<h3>Authorization Failed</h3><p>Reason: {error_reason}</p>",
            status_code=400
        )

    # 1. Validate CSRF State
    saved_state = request.cookies.get("oauth_state")
    if not saved_state or not returned_state or not secrets.compare_digest(saved_state, returned_state):
        raise HTTPException(status_code=403, detail="Invalid OAuth state parameter. Possible CSRF attack.")

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code.")

    token_url = f"https://facebook.com{GRAPH_API_VERSION}/oauth/access_token"

    async with httpx.AsyncClient() as client:
        # 2. Exchange authorization code for a short-lived token (~1-2 hours)
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
            return HTMLResponse(
                content=f"<h3>Short-Lived Token Error</h3><pre>{short_data}</pre>",
                status_code=400
            )

        short_lived_token = short_data.get("access_token")

        # 3. Exchange short-lived token for a 60-day long-lived token
        long_res = await client.get(
            token_url,
            params={
                "grant_type": "fb_exchange_token",
                "client_id": META_APP_ID,
                "client_secret": META_APP_SECRET,
                "fb_exchange_token": short_lived_token,
            },
        )
        long_data = long_res.json()

        if "error" in long_data:
            return HTMLResponse(
                content=f"<h3>Long-Lived Token Error</h3><pre>{long_data}</pre>",
                status_code=400
            )

    long_lived_token = long_data.get("access_token")
    expires_in = long_data.get("expires_in", "unknown")  # Typically ~5184000 seconds (60 days)

    # TODO: Store `long_lived_token` and its expiration timestamp in your database
    print(f"Long-lived token acquired (expires in {expires_in}s): {long_lived_token[:12]}...")

    # 4. Clear the temporary state cookie and return success response
    response = HTMLResponse(
        content=f"""
        <html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h2>Meta Account Connected!</h2>
                <p>Long-lived access token generated (valid for ~60 days).</p>
                <p>You may now close this tab.</p>
            </body>
        </html>
        """
    )
    response.delete_cookie("oauth_state")
    return response
