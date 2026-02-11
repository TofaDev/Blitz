#!/usr/bin/env python3

import sys
import asyncio
import inspect
from typing import Any

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.encoders import jsonable_encoder
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, Field, create_model

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


def _build_request_model(method_name: str, func: Any) -> type[BaseModel] | None:
    fields: dict[str, tuple[Any, Any]] = {}
    signature = inspect.signature(func)

    for name, param in signature.parameters.items():
        if name == 'self':
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue

        annotation = param.annotation if param.annotation is not inspect._empty else Any
        default = param.default if param.default is not inspect._empty else ...
        fields[name] = (annotation, default)

    if not fields:
        return None

    return create_model(f'{method_name.capitalize()}Request', **fields)


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
            'http_method': 'POST',
            'path': f'/call/{name}',
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


def _call_with_kwargs(func: Any, kwargs: dict[str, Any]) -> CallResponse:
    try:
        result = func(**kwargs)
    except TypeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return CallResponse(result=jsonable_encoder(result))


def _register_method_routes():
    for method_name, func in ALLOWED_METHODS.items():
        request_model = _build_request_model(method_name, func)
        description = (func.__doc__ or '').strip() or None

        if request_model is None:
            def endpoint(func=func):
                return _call_with_kwargs(func, {})
        else:
            def endpoint(body: request_model, func=func):  # type: ignore[name-defined]
                return _call_with_kwargs(func, body.model_dump())

        endpoint.__name__ = f'call_{method_name}'
        app.post(
            f'/call/{method_name}',
            response_model=CallResponse,
            dependencies=[Depends(require_token)],
            summary=f'Call {method_name}',
            description=description,
        )(endpoint)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    security_schemes = openapi_schema.setdefault('components', {}).setdefault('securitySchemes', {})
    security_schemes['ApiTokenAuth'] = {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Set API token. You can use raw token or "Bearer <token>".',
    }

    for path, methods in openapi_schema.get('paths', {}).items():
        if path == '/health':
            continue
        for operation in methods.values():
            operation.setdefault('security', []).append({'ApiTokenAuth': []})

    app.openapi_schema = openapi_schema
    return app.openapi_schema


_register_method_routes()
app.openapi = _custom_openapi  # type: ignore[assignment]


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
