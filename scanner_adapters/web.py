"""Authenticated Eevx UI and routes, without starting Rotomina background tasks."""
import asyncio
import secrets
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from .eevx import AdapterError, device_uuid, from_environment, renewable_session
from .session import SessionError


def router(load_config, save_config, config_lock, templates, status_cache=None):
    routes = APIRouter()

    def authenticate(request, mutation=False):
        if not request.session.get('logged_in'):
            raise AdapterError('Log into Rotomina first.', 401)
        expected = request.session.get('eevx_csrf', '')
        if mutation and (not expected or not secrets.compare_digest(
                request.headers.get('X-CSRF-Token', ''), expected)):
            raise AdapterError('Reload the Eevx page before saving.', 403)

    async def read_body(request):
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > 8192:
                raise AdapterError('Request too large.', 413)
        import json
        try:
            body = json.loads(raw)
            if not isinstance(body, dict):
                raise ValueError()
            return body
        except (ValueError, UnicodeDecodeError):
            raise AdapterError('Expected a JSON object.', 400) from None

    def binding(ip):
        devices = load_config().get('devices', [])
        matches = [d for d in devices if d.get('ip') == ip and d.get('scanner_type') == 'eevx']
        if len(matches) != 1:
            raise AdapterError('Select a linked Eevx device.', 404)
        return device_uuid(matches[0].get('eevx_device_id'))

    @routes.get('/eevx')
    async def page(request: Request):
        authenticate(request)
        request.session.setdefault('eevx_csrf', secrets.token_urlsafe(32))
        return templates.TemplateResponse(request=request, name='eevx.html', context={'request': request,
            'devices': load_config().get('devices', []), 'csrf': request.session['eevx_csrf']})

    @routes.get('/api/eevx/fleet')
    async def fleet(request: Request):
        authenticate(request)
        linked = [d for d in load_config().get('devices', []) if d.get('scanner_type') == 'eevx']
        if not linked:
            return JSONResponse({'devices': []}, headers={'Cache-Control': 'no-store'})
        statuses = await from_environment().statuses()
        result = []
        import time
        for device in linked:
            matches = [s for s in statuses if s.get('id') == device.get('eevx_device_id')]
            snapshot = matches[0] if len(matches) == 1 else {
                'id': device.get('eevx_device_id'), 'name': device.get('display_name'),
                'fresh': False, 'state': 'unavailable', 'observed': {}}
            cached = (status_cache or {}).get(device['ip'], {})
            rotom_fresh = time.time() - cached.get('last_update', 0) <= 30
            result.append(dict(snapshot, ip=device['ip'],
                mem_free=cached.get('mem_free') if rotom_fresh else None,
                runtime=cached.get('runtime') if rotom_fresh else None))
        return JSONResponse({'devices': result}, headers={'Cache-Control': 'no-store'})

    @routes.get('/api/eevx/devices')
    async def devices(request: Request):
        authenticate(request)
        available = await from_environment().devices()
        linked = {d.get('eevx_device_id') for d in load_config().get('devices', [])
                  if d.get('scanner_type') == 'eevx'}
        return JSONResponse({'devices': [dict(d, linked=d['id'] in linked) for d in available]},
                            headers={'Cache-Control': 'no-store'})

    @routes.get('/api/eevx/status')
    async def status(request: Request, ip: str):
        authenticate(request)
        result = await from_environment().status(binding(ip))
        # Keep exact Rotom origin synchronized after a dashboard rename.
        with config_lock:
            config = load_config()
            for device in config.get('devices', []):
                if device.get('ip') == ip and device.get('eevx_device_id') == result['id']:
                    origin = 'LocalScanner-' + result['name']
                    if device.get('eevx_rotom_origin') != origin:
                        device['eevx_rotom_origin'] = origin
                        save_config(config)
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})

    @routes.post('/api/eevx/login')
    async def login(request: Request):
        authenticate(request, True)
        body = await read_body(request)
        email, password = body.get('email'), body.get('password')
        if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
            raise AdapterError('Enter your Mapping email and password.', 400)
        try:
            await asyncio.to_thread(renewable_session().login, email, password)
        except SessionError as exc:
            raise AdapterError(str(exc), 403) from None
        return JSONResponse({'connected': True}, headers={'Cache-Control': 'no-store'})

    @routes.get('/api/eevx/operation')
    async def operation_status(request: Request, ip: str):
        authenticate(request)
        return JSONResponse(await from_environment().operation_status(binding(ip)), headers={'Cache-Control': 'no-store'})

    @routes.post('/api/eevx/operation')
    async def operation(request: Request):
        authenticate(request, True)
        body = await read_body(request)
        result = await from_environment().operate(binding(body.get('ip')), body.get('revision'),
            body.get('operationId'), body.get('kind'), body.get('versionCode'))
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})

    @routes.post('/api/eevx/bind')
    async def bind(request: Request):
        authenticate(request, True)
        body = await read_body(request)
        ip = body.get('ip', '')
        mapping_id = device_uuid(body.get('mapping_id'))
        current = await from_environment().status(mapping_id)
        # Explicit registration avoids upstream's automatic MapWorld setup pipeline.
        if not isinstance(ip, str) or len(ip) > 100 or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_' for c in ip):
            raise AdapterError('Enter an ADB serial or host:port.', 400)
        import re
        if re.fullmatch(r'\d{1,3}(?:\.\d{1,3}){3}', ip):
            ip += ':5555'
        with config_lock:
            config = load_config()
            # Keep existing ADB bindings stable when linking again from the picker.
            existing = next((d for d in config['devices']
                             if d.get('eevx_device_id') == mapping_id
                             and d.get('scanner_type') == 'eevx'), None)
            if not ip:
                ip = existing['ip'] if existing else 'eevx-' + mapping_id
            if any(d.get('eevx_device_id') == mapping_id and d.get('ip') != ip for d in config.get('devices', [])):
                raise AdapterError('This Mapping identity is already linked.', 409)
            target = next((d for d in config['devices'] if d.get('ip') == ip), None)
            if target is not None and target.get('scanner_type') != 'eevx':
                raise AdapterError('Existing MapWorld entry: migrate its scanner_type while Rotomina is stopped; see docs/eevx.md.', 409)
            if target is not None and target.get('eevx_device_id') not in (None, mapping_id):
                raise AdapterError('This address is linked to another Mapping device.', 409)
            if target is None:
                target = {'ip': ip}
                config['devices'].append(target)
            target.update(scanner_type='eevx', eevx_device_id=mapping_id,
                          eevx_rotom_origin='LocalScanner-' + current['name'],
                          display_name=current['name'], control_enabled=False)
            save_config(config)
            if not any(d.get('ip') == ip and d.get('eevx_device_id') == mapping_id
                       for d in load_config().get('devices', [])):
                raise AdapterError('Could not persist the Eevx binding.', 503)
        return {'linked': True}

    @routes.post('/api/eevx/control')
    async def control(request: Request):
        authenticate(request, True)
        body = await read_body(request)
        result = await from_environment().configure(binding(body.get('ip')),
                                                   body.get('revision'), body.get('changes', {}))
        return JSONResponse(result, headers={'Cache-Control': 'no-store'})

    return routes
