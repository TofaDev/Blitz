#!/usr/bin/env python3

import sys
import asyncio
import inspect
from typing import Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field

from config import CONFIGS

HYSTERIA_CORE_DIR = '/etc/hysteria/core'
sys.path.append(HYSTERIA_CORE_DIR)

import cli_api  # type: ignore

INTERNAL_METHODS = {
    'run_cmd',
    'run_cmd_and_stream',
    'generate_password',
}


def _build_allowed_methods() -> dict[str, Any]:
    methods: dict[str, Any] = {}
    for name, func in inspect.getmembers(cli_api, inspect.isfunction):
        if func.__module__ != cli_api.__name__:
            continue
        if name.startswith('_') or name in INTERNAL_METHODS:
            continue
        methods[name] = func
    return methods


ALLOWED_METHODS = _build_allowed_methods()


class CallRequest(BaseModel):
    method: str = Field(..., description='cli_api function name')
    args: list[Any] = Field(default_factory=list, description='Positional arguments')
    kwargs: dict[str, Any] = Field(default_factory=dict, description='Keyword arguments')


class CallResponse(BaseModel):
    ok: bool = True
    result: Any | None = None


def _extract_token(authorization: str | None, x_api_token: str | None) -> str | None:
    token = authorization or x_api_token
    if not token:
        return None
    if token.lower().startswith('bearer '):
        return token.split(' ', 1)[1]
    return token


def require_token(
    authorization: str | None = Header(default=None),
    x_api_token: str | None = Header(default=None),
) -> None:
    if not CONFIGS.API_TOKEN:
        raise HTTPException(status_code=500, detail='API token is not configured.')

    token = _extract_token(authorization, x_api_token)
    if not token or token != CONFIGS.API_TOKEN:
        raise HTTPException(status_code=401, detail='Invalid API token.')


app = FastAPI(
    title='Blitz API Server',
    description='API server exposing cli_api methods for Hysteria2 management.',
    version='0.1.0',
    debug=CONFIGS.DEBUG,
    root_path=f'/{CONFIGS.ROOT_PATH}',
)


@app.get('/health')
def health_check():
    return {'status': 'ok'}


@app.get('/methods', dependencies=[Depends(require_token)])
def list_methods():
    methods = []
    for name, func in sorted(ALLOWED_METHODS.items()):
        methods.append({
            'name': name,
            'signature': str(inspect.signature(func)),
            'doc': (func.__doc__ or '').strip() or None,
        })
    return {'methods': methods}


@app.post('/call', response_model=CallResponse, dependencies=[Depends(require_token)])
def call_method(body: CallRequest):
    if body.method not in ALLOWED_METHODS:
        raise HTTPException(status_code=404, detail=f"Unknown method '{body.method}'.")

    func = ALLOWED_METHODS[body.method]
    try:
        result = func(*body.args, **body.kwargs)
    except TypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return CallResponse(result=jsonable_encoder(result))


if __name__ == '__main__':
    from hypercorn.config import Config
    from hypercorn.asyncio import serve
    from hypercorn.middleware import ProxyFixMiddleware

    config = Config()
    config.debug = CONFIGS.DEBUG
    config.bind = [f"{CONFIGS.LISTEN_ADDRESS}:{CONFIGS.LISTEN_PORT}"]
    config.accesslog = '-'
    config.errorlog = '-'

    app_wrapped = ProxyFixMiddleware(app, 'legacy')
    asyncio.run(serve(app_wrapped, config))
