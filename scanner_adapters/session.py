"""Server-side Supabase session renewal; refresh-token rotation is durably serialized."""
import base64
import fcntl
import json
import os
import tempfile
import time
from pathlib import Path

import httpx


class SessionError(Exception):
    pass


def claims(token):
    try:
        if not isinstance(token, str) or len(token) > 16384 or any(c.isspace() for c in token):
            raise ValueError()
        part = token.split('.')[1]
        result = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)))
        if result.get('role') != 'authenticated' or not result.get('sub') or type(result.get('exp')) not in (int, float):
            raise ValueError()
        return result
    except (ValueError, IndexError, AttributeError, TypeError):
        raise SessionError('Invalid owner session. Sign in again.') from None


def private_read(path):
    try:
        with path.open() as stream:
            stat = os.fstat(stream.fileno())
            if stat.st_mode & 0o077 or stat.st_size > 32768:
                raise ValueError()
            return json.load(stream)
    except (OSError, ValueError):
        raise SessionError('Owner session must be a private JSON file. Sign in again.') from None


def atomic_write(path, value):
    fd, temporary = tempfile.mkstemp(prefix='.session-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class OwnerSession:
    def __init__(self, path, auth_url, anon_key, transport=None, clock=time.time):
        self.path = Path(path)
        url = httpx.URL(auth_url)
        if url.scheme != 'https' or not url.host or url.username or url.password or url.query or url.fragment or url.path not in ('', '/'):
            raise SessionError('Configure a trusted HTTPS Supabase origin.')
        if not anon_key or len(anon_key) > 16384:
            raise SessionError('Configure the public Supabase API key.')
        self.auth_url, self.anon_key = auth_url.rstrip('/'), anon_key
        self.transport, self.clock = transport, clock

    def token(self):
        try:
            # Stable sidecar lock survives atomic replacement and spans processes.
            fd = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
            with os.fdopen(fd, 'w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                session = private_read(self.path)
                original = claims(session.get('access_token'))
                if original['exp'] > self.clock() + 60:
                    return session['access_token']
                if session.get('renewal_uncertain'):
                    raise SessionError('Session renewal is uncertain. Sign in again; it will not be replayed.')
                refresh = session.get('refresh_token')
                if not isinstance(refresh, str) or not refresh or len(refresh) > 16384:
                    raise SessionError('A renewable owner session is required. Sign in again.')
                # If we die after the server rotates the token, never replay the old token blindly.
                atomic_write(self.path, {**session, 'renewal_uncertain': True})
                with httpx.Client(timeout=15, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                    response = client.post(self.auth_url + '/auth/v1/token?grant_type=refresh_token',
                        headers={'apikey': self.anon_key}, json={'refresh_token': refresh})
                if response.status_code != 200:
                    raise SessionError('Owner session renewal failed. Sign in again.')
                renewed = response.json()
                updated = claims(renewed.get('access_token'))
                if updated['sub'] != original['sub'] or updated['exp'] <= self.clock() + 60:
                    raise SessionError('Renewed identity or expiry did not match. Sign in again.')
                next_refresh = renewed.get('refresh_token')
                if not isinstance(next_refresh, str) or not next_refresh or len(next_refresh) > 16384:
                    raise SessionError('Invalid renewed session. Sign in again.')
                atomic_write(self.path, {'access_token': renewed['access_token'], 'refresh_token': next_refresh})
                return renewed['access_token']
        except SessionError:
            raise
        except (OSError, ValueError, TypeError, AttributeError, httpx.HTTPError):
            raise SessionError('Owner session renewal unavailable. Check the private session file or sign in again.') from None

    def login(self, email, password):
        # Password is transient and never persisted or returned. Caller uses the same lock as renewal.
        try:
            fd = os.open(str(self.path) + '.lock', os.O_CREAT | os.O_RDWR, 0o600)
        except OSError:
            raise SessionError('Configure a writable private session directory.') from None
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                with httpx.Client(timeout=15, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                    response = client.post(self.auth_url + '/auth/v1/token?grant_type=password',
                        headers={'apikey': self.anon_key}, json={'email': email, 'password': password})
                if response.status_code != 200:
                    raise SessionError('Mapping sign-in failed. Check your verified account credentials.')
                session = response.json()
                parsed = claims(session.get('access_token'))
                if parsed['exp'] <= self.clock() + 60 or not isinstance(session.get('refresh_token'), str) or not session['refresh_token']:
                    raise SessionError('A renewable owner session was not returned.')
                atomic_write(self.path, {'access_token': session['access_token'], 'refresh_token': session['refresh_token']})
            except (OSError, ValueError, TypeError, AttributeError, httpx.HTTPError):
                raise SessionError('Mapping sign-in unavailable.') from None
