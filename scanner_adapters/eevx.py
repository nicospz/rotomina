"""Eevx owner API adapter. Never uses Android agent or service-role credentials."""
import base64
import json
import os
import time
from datetime import datetime
from pathlib import Path
from uuid import UUID

import httpx

DEFAULT_URL = 'https://ygyaoulwimaknuebagjf.supabase.co/functions/v1/store'


class AdapterError(Exception):
    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


def device_uuid(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError):
        raise AdapterError('A Mapping device UUID is required.', 400) from None


def public_status(device, now=None):
    # Allowlist: never send arbitrary backend fields or credentials to browsers.
    result = {key: device.get(key) for key in (
        'id', 'name', 'workers', 'rotom_id', 'rotom_url', 'desired_running',
        'revision', 'applied_revision', 'last_seen', 'licensed', 'revoked')}
    observed = device.get('observed') or {}
    result['observed'] = {key: observed.get(key) for key in (
        'state', 'workers', 'connected', 'active', 'successfulRpc', 'failedRpc',
        'restarts', 'lastRestartAt', 'error')}
    try:
        age = (time.time() if now is None else now) - datetime.fromisoformat(
            device['last_seen'].replace('Z', '+00:00')).timestamp()
        result['age_seconds'] = max(0, round(age))
        result['fresh'] = -5 <= age <= 30
    except (ValueError, TypeError, KeyError):
        result.update(age_seconds=None, fresh=False)
    result['state'] = observed.get('state', 'unknown') if result['fresh'] else 'unknown'
    result['recovery_owner'] = 'eevx'
    result['capabilities'] = ['status', 'start', 'stop', 'configure']
    return result


class EevxAdapter:
    def __init__(self, token_provider, base_url=DEFAULT_URL, transport=None):
        url = httpx.URL(base_url)
        if url.scheme != 'https' or url.username or url.password or url.query or url.fragment:
            raise AdapterError('Mapping API requires an HTTPS URL without credentials or query.', 503)
        self.base_url = base_url.rstrip('/')
        self.token_provider = token_provider
        self.transport = transport

    async def _request(self, method, path, body=None):
        token = self.token_provider()
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False,
                                        transport=self.transport, trust_env=False) as client:
                response = await client.request(method, self.base_url + path,
                    headers={'Authorization': 'Bearer ' + token}, json=body)
        except httpx.HTTPError:
            raise AdapterError('Mapping API unavailable; command was not retried.') from None
        if response.status_code in (401, 403):
            raise AdapterError('Mapping login expired or access denied. Renew the owner credential.', 403)
        if response.status_code == 409:
            raise AdapterError('Device changed elsewhere. Refresh before sending another command.', 409)
        if not response.is_success:
            raise AdapterError('Mapping rejected the request; refresh device status.',
                               400 if response.status_code == 400 else 502)
        try:
            return response.json()
        except ValueError:
            raise AdapterError('Invalid Mapping response.') from None

    async def device(self, mapping_id):
        mapping_id = device_uuid(mapping_id)
        data = await self._request('GET', '/mapping')
        devices = data.get('devices', []) if isinstance(data, dict) else []
        matches = [d for d in devices if isinstance(d, dict) and d.get('id') == mapping_id]
        if len(matches) != 1:
            raise AdapterError('Mapping device not found or identity ambiguous.', 404)
        return matches[0]

    async def status(self, mapping_id):
        return public_status(await self.device(mapping_id))

    async def configure(self, mapping_id, revision, changes):
        if type(revision) is not int or revision < 1:
            raise AdapterError('Refresh to obtain a valid revision.', 400)
        allowed = {'workers', 'running', 'name', 'rotomId'}
        if not isinstance(changes, dict) or not changes or set(changes) - allowed:
            raise AdapterError('Unsupported configuration field.', 400)
        current = await self.device(mapping_id)
        if current.get('revision') != revision:
            raise AdapterError('Device changed elsewhere. Refresh before saving.', 409)
        workers = changes.get('workers', current.get('workers'))
        running = changes.get('running', current.get('desired_running'))
        if type(workers) is not int or not 1 <= workers <= 1000 or type(running) is not bool:
            raise AdapterError('Choose 1–1000 workers and a boolean running state.', 400)
        body = dict(revision=revision, workers=workers, running=running)
        if 'name' in changes or 'rotomId' in changes:
            name = changes.get('name', current.get('name'))
            if not isinstance(name, str) or not name.strip() or len(name.strip()) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name):
                raise AdapterError('Enter a device name of 1–80 characters.', 400)
            body.update(name=name.strip(), rotomId=device_uuid(changes.get('rotomId', current.get('rotom_id'))))
        result = await self._request('POST', '/mapping/devices/' + device_uuid(mapping_id), body)
        if not isinstance(result, dict) or type(result.get('revision')) is not int:
            raise AdapterError('Command acknowledgement unavailable; refresh before retrying.')
        return {'accepted': True, 'revision': result['revision'], 'observed_completion': False}


def owner_token():
    """Read each time so an external login helper can atomically rotate the file."""
    try:
        path = Path(os.environ['EEVX_OWNER_TOKEN_FILE'])
        if path.stat().st_mode & 0o077:
            raise ValueError()
        token = path.read_text().strip()
        payload = token.split('.')[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
        # Only a user session; signature/access validation remains the API's job.
        if claims.get('role') != 'authenticated' or not claims.get('sub') or claims.get('exp', 0) <= time.time():
            raise ValueError()
        if len(token) > 16384 or '\n' in token or '\r' in token:
            raise ValueError()
        return token
    except (KeyError, OSError, ValueError, IndexError, TypeError):
        raise AdapterError('Configure a private, current owner JWT file (EEVX_OWNER_TOKEN_FILE).', 503) from None


def from_environment():
    return EevxAdapter(owner_token, os.environ.get('EEVX_MAPPING_API_URL', DEFAULT_URL))
