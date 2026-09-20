import base64
import concurrent.futures
import json
import os

import httpx
import pytest
from scanner_adapters.session import OwnerSession, SessionError, atomic_write


def token(exp=2000, sub='owner', role='authenticated'):
    payload=base64.urlsafe_b64encode(json.dumps(dict(exp=exp,sub=sub,role=role)).encode()).decode().rstrip('=')
    return 'header.'+payload+'.signature'


def setup(tmp_path, handler, session=None):
    path=tmp_path/'owner.json'
    atomic_write(path, session or {'access_token':token(1000),'refresh_token':'original-secret'})
    return path,OwnerSession(path,'https://auth.example','public-key',httpx.MockTransport(handler),lambda:1000)


def test_refresh_rotates_privately_and_only_once_across_concurrent_calls(tmp_path):
    calls=[]
    def handler(request):
        calls.append(json.loads(request.content))
        return httpx.Response(200,json={'access_token':token(),'refresh_token':'rotated-secret'})
    path,session=setup(tmp_path,handler)
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(lambda _:session.token(),range(8))) == [token()]*8
    assert calls == [{'refresh_token':'original-secret'}]
    assert json.loads(path.read_text()) == {'access_token':token(),'refresh_token':'rotated-secret'}
    assert os.stat(path).st_mode & 0o077 == 0


@pytest.mark.parametrize('response',[
    {'access_token':token(sub='other'),'refresh_token':'new'},
    {'access_token':token(role='service_role'),'refresh_token':'new'},
    {'access_token':token(1001),'refresh_token':'new'},
    {'access_token':token()},
])
def test_refresh_rejects_identity_privilege_or_invalid_rotation(tmp_path,response):
    path,session=setup(tmp_path,lambda r:httpx.Response(200,json=response))
    with pytest.raises(SessionError):session.token()
    assert json.loads(path.read_text())['renewal_uncertain'] is True


def test_lost_refresh_response_does_not_replay_old_refresh_token(tmp_path):
    calls=[]
    def handler(request):
        calls.append(1)
        raise httpx.ReadTimeout('SECRET')
    path,session=setup(tmp_path,handler)
    for _ in range(2):
        with pytest.raises(SessionError) as error:session.token()
        assert 'SECRET' not in str(error.value)
    assert len(calls)==1


def test_login_persists_only_session_and_replaces_uncertain_state(tmp_path):
    path,session=setup(tmp_path,lambda r:httpx.Response(200,json={
        'access_token':token(),'refresh_token':'rotated','user':{'email':'private'}}))
    session.login('owner@example.test','password-secret')
    assert json.loads(path.read_text())=={'access_token':token(),'refresh_token':'rotated'}


def test_insecure_session_permissions_are_rejected(tmp_path):
    path,session=setup(tmp_path,lambda r:pytest.fail('must not connect'))
    path.chmod(0o644)
    with pytest.raises(SessionError):session.token()
