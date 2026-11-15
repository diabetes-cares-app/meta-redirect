import os
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse

app = FastAPI()

# Load credentials from Railway Environment Variables
META_APP_ID = os.getenv("META_APP_ID")
META_APP_SECRET = os.getenv("META_APP_SECRET")
# Must match the EXACT URL registered in your Meta App Dashboard
REDIRECT_URI = os.getenv("REDIRECT_URI") 

@app.get("/")
async def home():
    return {"status": "Meta Redirect Server is Running"}

@app.get("/auth/meta/callback")
async def meta_callback(request: Request):
    """
    Meta redirects the user's browser here after they approve permissions.
    """
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    error_reason = request.query_params.get("error_reason")

    # 1. Handle if the user clicked "Cancel" or an error occurred
    if error:
        return HTMLResponse(
            content=f"<h3>Authorization Failed</h3><p>Reason: {error_reason}</p>",
            status_code=400
        )

    if not code:
        raise HTTPException(status_code=400, detail="Missing authorization code from Meta.")

    # 2. Exchange the temporary 'code' for a real Access Token
    token_url = "https://facebook.com"
    params = {
        "client_id": META_APP_ID,
        "redirect_uri": REDIRECT_URI,
        "client_secret": META_APP_SECRET,
        "code": code,
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(token_url, params=params)
        token_data = response.json()

    if "error" in token_data:
        return HTMLResponse(
            content=f"<h3>Token Exchange Failed</h3><pre>{token_data}</pre>",
            status_code=400
        )

    access_token = token_data.get("access_token")

    # TODO: Save `access_token` securely to your database here!
    print(f"Successfully retrieved token: {access_token[:10]}...")

    # 3. Show a clean confirmation page to the user (or redirect them to your frontend)
    return HTMLResponse(
        content="""
        <html>
            <body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
                <h2>Connection Successful!</h2>
                <p>Your Meta account has been linked. You can safely close this window.</p>
            </body>
        </html>
        """
    )
