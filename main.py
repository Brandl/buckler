from fastapi import FastAPI, Form, Request, HTTPException, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi_jwt_auth import AuthJWT
from fastapi_jwt_auth.exceptions import AuthJWTException
from pydantic import BaseSettings
from contextlib import asynccontextmanager

import pyotp
import os
import io
import qrcode


class Settings(BaseSettings):
    totp_secret: str = ""
    static_secret: str = ""
    authjwt_secret_key: str = "your-secret-key"
    authjwt_token_location: set = ('headers','cookies')
    authjwt_cookie_csrf_protect: bool = False
    authjwt_cookie_domain: str = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not settings.totp_secret:
        settings.totp_secret = pyotp.random_base32()
        uri = pyotp.totp.TOTP(settings.totp_secret).provisioning_uri(
            name="totp@auth.server", issuer_name="Secure Login"
        )
        qr = qrcode.QRCode()
        qr.add_data(uri)
        f = io.StringIO()
        qr.print_ascii(out=f)
        f.seek(0)
        print("Generated TOTP SECRET: ", settings.totp_secret)
        print("URI: ", uri)
        print(f.read())
    if not settings.static_secret:
        raise RuntimeError("STATIC_SECRET environment variables must be set")

    yield


settings = Settings()
app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory=".")

@AuthJWT.load_config
def get_config():
    return settings


@app.get("/debug")
async def debug(request: Request):
    print("#### REQUEST #### \n", request.__dict__)
    print("#### SETTINGS #### \n", settings.__dict__)
    return "DEBUG INFO HAS BEEN PRINTED TO LOG"


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request, warning: str = ""):
    return templates.TemplateResponse("login.html", {"request": request, "warning": warning})


@app.post("/login")
async def validate(
    request: Request,
    next: str = "",
    totp: str = Form(...),
    secret: str = Form(...),
    Authorize: AuthJWT = Depends(),
):
    totp_obj = pyotp.totp.TOTP(settings.totp_secret)
    totp_correct = totp_obj.verify(totp)
    secret_correct = secret == settings.static_secret
    if totp_correct and secret_correct:
        access_token = Authorize.create_access_token(subject="user")
        response = RedirectResponse(next or "/", status_code=303)
        Authorize.set_access_cookies(access_token, response)
        return response
    else:
        print(
            f"Incorrect {'SECRET' if not secret_correct else ''}/{'TOTP' if not totp_correct else''} from {request.headers.get('user-agent')} @ {request.client.host}"
        )
        warning = "Incorrect login credentials. Please try again."
        return await login(request, warning)


@app.get("/auth")
async def auth(Authorize: AuthJWT = Depends()):
    try:
        Authorize.jwt_required()
    except AuthJWTException as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    return Response(status_code=status.HTTP_200_OK)
