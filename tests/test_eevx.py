import asyncio
import ast
import copy
import json
import threading
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from fastapi.testclient import TestClient
from scanner_adapters.eevx import EevxAdapter, AdapterError, public_status, owner_token
from scanner_adapters.web import router

ID = 'de989198-e0c7-4eba-adf2-ce5bda4882fd'
ROTOM = 'cddf76e0-8743-43e0-9cbd-07925ab87cc1'
DEVICE = dict(id=ID, name='phone', workers=50, desired_running=False,
              revision=7, applied_revision=7, rotom_id=ROTOM,
              observed={'state':'stopped'}, last_seen='2026-09-20T00:00:00Z')


def adapter(handler):
    return EevxAdapter(lambda: 'test-owner', transport=httpx.MockTransport(handler))


def test_config_preserves_stopped_intent_and_does_not_send_secrets():
    posts = []
    def handle(request):
        assert request.headers['authorization'] == 'Bearer test-owner'
        if request.method == 'GET':
            return httpx.Response(200, json={'devices':[DEVICE]})
        posts.append(json.loads(request.content))
        return httpx.Response(200, json={'revision':8})
    result = asyncio.run(adapter(handle).configure(ID, 7, {'workers':150}))
    assert posts == [{'revision':7,'workers':150,'running':False}]
    assert result == {'accepted':True,'revision':8,'observed_completion':False}


def test_server_conflict_between_read_and_write_is_not_retried():
    calls=[]
    def handle(request):
        calls.append(request.method)
        return httpx.Response(200, json={'devices':[DEVICE]}) if request.method == 'GET' else httpx.Response(409)
    with pytest.raises(AdapterError) as error:
        asyncio.run(adapter(handle).configure(ID, 7, {'running':True}))
    assert error.value.status == 409
    assert calls == ['GET','POST']


def test_old_start_cannot_override_new_stop():
    current=dict(DEVICE, revision=8)
    def handle(request):
        assert request.method == 'GET'
        return httpx.Response(200, json={'devices':[current]})
    with pytest.raises(AdapterError) as error:
        asyncio.run(adapter(handle).configure(ID, 7, {'running':True}))
    assert error.value.status == 409


@pytest.mark.parametrize('changes', [{'workers':True},{'workers':1001},{'running':'true'},
    {'restart':True},{'apk':'bad'},{'rotomToken':'secret'},{'name':'bad\nname'},[],None])
def test_reject_invalid_configuration(changes):
    def handle(request):
        assert request.method == 'GET'
        return httpx.Response(200, json={'devices':[DEVICE]})
    with pytest.raises(AdapterError):
        asyncio.run(adapter(handle).configure(ID, 7, changes))


def test_exact_identity_not_display_name():
    wrong=dict(DEVICE, id=ROTOM)
    with pytest.raises(AdapterError):
        asyncio.run(adapter(lambda r: httpx.Response(200,json={'devices':[wrong]})).status(ID))


def test_stale_is_unknown_and_response_redacted():
    result=public_status(dict(DEVICE, agent_token='SECRET', observed={'state':'running','secret':'SECRET'}), now=9999999999)
    assert result['state'] == 'unknown' and not result['fresh']
    assert 'SECRET' not in json.dumps(result)


@pytest.mark.parametrize('status', [302,401,403,500])
def test_errors_never_echo_backend_secrets_or_follow_redirects(status):
    with pytest.raises(AdapterError) as error:
        asyncio.run(adapter(lambda r: httpx.Response(status, text='SECRET',headers={'location':'https://evil.example'})).status(ID))
    assert 'SECRET' not in str(error.value)


def test_timeout_not_retried():
    calls=[]
    def handle(request):
        calls.append(request.method)
        if request.method=='GET': return httpx.Response(200,json={'devices':[DEVICE]})
        raise httpx.ReadTimeout('SECRET')
    with pytest.raises(AdapterError) as error:
        asyncio.run(adapter(handle).configure(ID,7,{'running':False}))
    assert calls == ['GET','POST'] and 'SECRET' not in str(error.value)


def test_reject_service_role_token(tmp_path, monkeypatch):
    import base64
    payload=base64.urlsafe_b64encode(json.dumps({'role':'service_role','exp':9999999999,'sub':'x'}).encode()).decode().rstrip('=')
    path=tmp_path/'jwt'; path.write_text('x.'+payload+'.x');path.chmod(0o600)
    monkeypatch.setenv('EEVX_OWNER_TOKEN_FILE',str(path))
    with pytest.raises(AdapterError): owner_token()


# Exercise actual upstream function guards without importing its background globals.
@pytest.mark.parametrize('name', ['stop_apps','optimized_app_start','optimized_login_sequence',
    'read_device_furtif_config','write_device_furtif_config','write_device_discord_token',
    'ensure_device_token','install_mapworld','install_apk_for_device','optimized_apk_installation',
    'optimized_perform_installation','install_module_with_progress','run_device_setup',
    'clear_app_cache','uninstall_pogo','reclaim_storage','reboot_and_wait'])
def test_legacy_paths_exit_before_side_effects(name):
    tree=ast.parse(Path('main.py').read_text())
    node=next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    node.decorator_list=[]
    node.returns=None
    for arg in node.args.args: arg.annotation=None
    node.args.defaults=[]
    env={'is_eevx_device':lambda _:True}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'main.py','exec'),env)
    args=[None if a.arg=='self' else 'test-device' for a in node.args.args]
    result=env[name](*args)
    if isinstance(node,ast.AsyncFunctionDef): result=asyncio.run(result)
    assert result is None or result is False or result == {} or result[0] is False


def test_routes_auth_csrf_and_no_side_effect_registration():
    config={'devices':[]}
    app=FastAPI();app.add_middleware(SessionMiddleware,secret_key='test-only')
    @app.exception_handler(AdapterError)
    async def error(request,exc): return JSONResponse({'error':str(exc)},status_code=exc.status)
    @app.get('/test-login')
    async def login(request: __import__('fastapi').Request):
        request.session['logged_in']=True
        request.session['eevx_csrf']='csrf'
        return {}
    app.include_router(router(lambda:copy.deepcopy(config),lambda c:config.update(c),threading.RLock(),Jinja2Templates(directory='templates')))
    client=TestClient(app)
    assert client.get('/api/eevx/status',params={'ip':'phone'}).status_code==401
    client.get('/test-login')
    assert client.post('/api/eevx/bind',json={}).status_code==403
    headers={'X-CSRF-Token':'csrf'}
    fake=adapter(lambda r:httpx.Response(200,json={'devices':[DEVICE]}))
    with patch('scanner_adapters.web.from_environment',return_value=fake):
        assert client.post('/api/eevx/bind',json={'ip':'test:5555','mapping_id':ID},headers=headers).status_code==200
        assert config['devices'][0]['control_enabled'] is False
        assert client.get('/api/eevx/status',params={'ip':'test:5555'}).json()['id']==ID
        assert client.post('/api/eevx/bind',json={'ip':'another:5555','mapping_id':ID},headers=headers).status_code==409
    assert client.post('/api/eevx/control',json=[],headers=headers).status_code==400
    assert client.get('/eevx').status_code==200

@pytest.mark.parametrize('running', [True,False])
def test_start_stop_send_only_revision_checked_owner_control(running):
    posts=[]
    def handle(request):
        if request.method=='GET': return httpx.Response(200,json={'devices':[DEVICE]})
        assert request.url.path.endswith('/mapping/devices/'+ID)
        posts.append(json.loads(request.content))
        return httpx.Response(200,json={'revision':8})
    asyncio.run(adapter(handle).configure(ID,7,{'running':running}))
    assert posts == [dict(revision=7, workers=50, running=running)]


def test_saved_rotom_and_name_configuration():
    posts=[]
    def handle(request):
        if request.method=='GET': return httpx.Response(200,json={'devices':[DEVICE]})
        posts.append(json.loads(request.content))
        return httpx.Response(200,json={'revision':8})
    asyncio.run(adapter(handle).configure(ID,7,{'name':'new name','rotomId':ROTOM,'workers':150}))
    assert posts == [dict(revision=7,workers=150,running=False,name='new name',rotomId=ROTOM)]


@pytest.mark.parametrize('name', ['get_device_rotom_config','save_device_rotom_config',
    'mitm_device_update','restart_apps','reboot_device'])
def test_legacy_routes_reject_eevx_before_adb(name):
    from fastapi import HTTPException
    tree=ast.parse(Path('main.py').read_text())
    node=next(n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name==name)
    node.decorator_list=[];node.returns=None;node.args.defaults=[]
    for arg in node.args.args: arg.annotation=None
    env={'is_eevx_device':lambda _:True,'HTTPException':HTTPException}
    exec(compile(ast.Module(body=[node],type_ignores=[]),'main.py','exec'),env)
    with pytest.raises(HTTPException) as error:
        result=env[name](*['test' for _ in node.args.args])
        if isinstance(node,ast.AsyncFunctionDef): asyncio.run(result)
    assert error.value.status_code==409


def test_rotom_identity_collisions_are_not_accepted():
    tree=ast.parse(Path('main.py').read_text())
    fn=next(n for n in ast.walk(tree) if isinstance(n,ast.AsyncFunctionDef) and n.name=='update_api_status')
    guard=next(n for n in ast.walk(fn) if isinstance(n,ast.If) and any(
        isinstance(x,ast.Name) and x.id=='exact_matches' for x in ast.walk(n)))
    env={'dev':{'scanner_type':'eevx','eevx_rotom_origin':'LocalScanner-phone'},
         'api_data':{'devices':[{'origin':'LocalScanner-phone'},{'origin':'LocalScanner-phone2'}]}}
    code=compile(ast.Module(body=[guard],type_ignores=[]),'main.py','exec')
    exec(code,env)
    assert env['device_data']=={'origin':'LocalScanner-phone'}
    env['api_data']['devices'].append({'origin':'LocalScanner-phone'})
    exec(code,env)
    assert env['device_data'] is None


def test_managed_operations_use_expected_revision_and_idempotency_id():
    posts=[]
    def handle(request):
        assert request.method=='POST'
        posts.append(json.loads(request.content))
        return httpx.Response(200,json={'operation':{'id':ROTOM,'state':'pending'}})
    asyncio.run(adapter(handle).operate(ID,7,ROTOM,'update',24))
    assert posts==[dict(revision=7,operationId=ROTOM,kind='update',versionCode=24)]


def test_management_capabilities_require_fresh_protocol_telemetry():
    from datetime import datetime
    current=datetime.fromisoformat(DEVICE['last_seen'].replace('Z','+00:00')).timestamp()
    supported=dict(DEVICE,observed={'managementProtocol':1,'appVersionCode':24})
    assert 'update' in public_status(supported,now=current)['capabilities']
    assert 'update' not in public_status(supported,now=current+100)['capabilities']
    assert 'update' not in public_status(DEVICE,now=current)['capabilities']


def test_login_and_management_routes_require_csrf_and_do_not_return_session_secrets():
    from fastapi import Request
    config={'devices':[{'ip':'phone','scanner_type':'eevx','eevx_device_id':ID}]}
    app=FastAPI();app.add_middleware(SessionMiddleware,secret_key='test-only')
    @app.exception_handler(AdapterError)
    async def error(request,exc):return JSONResponse({'error':str(exc)},status_code=exc.status)
    @app.get('/test-login')
    async def login(request:Request):
        request.session['logged_in']=True;request.session['eevx_csrf']='csrf';return {}
    app.include_router(router(lambda:config,lambda _:None,threading.RLock(),Jinja2Templates(directory='templates')))
    client=TestClient(app);client.get('/test-login')
    for path in ['login','operation']:
        assert client.post('/api/eevx/'+path,json={}).status_code==403
    with patch('scanner_adapters.web.renewable_session') as session:
        result=client.post('/api/eevx/login',json={'email':'owner@test','password':'SECRET'},headers={'X-CSRF-Token':'csrf'})
        assert result.json()=={'connected':True}
        session.return_value.login.assert_called_once_with('owner@test','SECRET')
        assert 'SECRET' not in result.text
    fake=adapter(lambda r:httpx.Response(200,json={'operation':{'state':'pending'}}))
    with patch('scanner_adapters.web.from_environment',return_value=fake):
        result=client.post('/api/eevx/operation',json={'ip':'phone','revision':7,'operationId':ROTOM,'kind':'restart'},headers={'X-CSRF-Token':'csrf'})
        assert result.status_code==200


def test_account_discovery_and_adb_free_linking():
    config = {'devices': []}
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key='test-only')
    @app.exception_handler(AdapterError)
    async def error(request, exc):
        return JSONResponse({'error': str(exc)}, status_code=exc.status)
    @app.get('/test-login')
    async def login(request: __import__('fastapi').Request):
        request.session.update(logged_in=True, eevx_csrf='csrf')
        return {}
    app.include_router(router(lambda: copy.deepcopy(config), lambda c: config.update(c),
                              threading.RLock(), Jinja2Templates(directory='templates')))
    client = TestClient(app)
    assert client.get('/api/eevx/devices').status_code == 401
    client.get('/test-login')
    headers = {'X-CSRF-Token': 'csrf'}
    def handle(request):
        assert request.method == 'GET'  # Discovery/linking never commands the scanner.
        return httpx.Response(200, json={'devices': [dict(DEVICE, agent_token='SECRET'),
            dict(DEVICE, id=ROTOM, revoked=True)], 'secret': 'SECRET'})
    with patch('scanner_adapters.web.from_environment', return_value=adapter(handle)):
        response = client.get('/api/eevx/devices')
        assert response.json() == {'devices': [{'id': ID, 'name': 'phone', 'linked': False}]}
        assert response.headers['cache-control'] == 'no-store'
        assert 'SECRET' not in response.text
        assert client.post('/api/eevx/bind', json={'mapping_id': ID}).status_code == 403
        assert client.post('/api/eevx/bind', json={'mapping_id': ROTOM[::-1]}, headers=headers).status_code == 404
        for body in ({'mapping_id': ID}, {'mapping_id': ID, 'ip': ''}):
            assert client.post('/api/eevx/bind', json=body, headers=headers).status_code == 200
        assert len(config['devices']) == 1
        assert config['devices'][0]['ip'] == 'eevx-' + ID
        assert config['devices'][0]['control_enabled'] is False
        assert client.get('/api/eevx/status', params={'ip': 'eevx-' + ID}).json()['id'] == ID
        assert client.get('/api/eevx/devices').json()['devices'][0]['linked'] is True
        # Relinking from discovery preserves an existing ADB address.
        config['devices'][0]['ip'] = 'phone:5555'
        assert client.post('/api/eevx/bind', json={'mapping_id': ID}, headers=headers).status_code == 200
        assert config['devices'][0]['ip'] == 'phone:5555'
        assert len(config['devices']) == 1
        # Do not silently replace another device's identity or a MapWorld record.
        config['devices'][0]['eevx_device_id'] = ROTOM
        assert client.post('/api/eevx/bind', json={'mapping_id': ID, 'ip': 'phone:5555'}, headers=headers).status_code == 409
        config['devices'][0]['scanner_type'] = 'mapworld'
        assert client.post('/api/eevx/bind', json={'mapping_id': ID, 'ip': 'phone:5555'}, headers=headers).status_code == 409
        page = client.get('/eevx').text
        assert 'id="available-devices"' in page
        assert 'name="ip" placeholder="ADB serial or host:port" required' not in page


def test_fleet_uses_one_request_redacts_and_filters_to_linked_devices():
    import time
    config = {'devices': [{'ip': 'eevx-' + ID, 'scanner_type': 'eevx',
                           'eevx_device_id': ID, 'display_name': 'phone'}]}
    cache = {'eevx-' + ID: {'last_update': time.time(), 'mem_free': 2048, 'runtime': 60}}
    app = FastAPI()
    app.add_middleware(SessionMiddleware, secret_key='test')
    @app.exception_handler(AdapterError)
    async def error(request, exc):
        return JSONResponse({'error': str(exc)}, status_code=exc.status)
    @app.get('/test-login')
    async def login(request: __import__('fastapi').Request):
        request.session['logged_in'] = True
        return {}
    app.include_router(router(lambda: config, lambda _: None, threading.RLock(),
                              Jinja2Templates(directory='templates'), cache))
    client = TestClient(app)
    assert client.get('/api/eevx/fleet').status_code == 401
    client.get('/test-login')
    calls = []
    def handle(request):
        calls.append(request)
        return httpx.Response(200, json={'devices': [dict(DEVICE, agent_token='SECRET'),
                                                      dict(DEVICE, id=ROTOM)]})
    with patch('scanner_adapters.web.from_environment', return_value=adapter(handle)):
        response = client.get('/api/eevx/fleet')
        assert len(calls) == 1
        assert 'SECRET' not in response.text
        rows = response.json()['devices']
        assert len(rows) == 1 and rows[0]['id'] == ID
        assert rows[0]['mem_free'] == 2048
        assert rows[0]['fresh'] is False and rows[0]['state'] == 'unknown'
        cache['eevx-' + ID]['last_update'] = 0
        assert client.get('/api/eevx/fleet').json()['devices'][0]['mem_free'] is None
        config['devices'][0]['eevx_device_id'] = 'unavailable'
        assert client.get('/api/eevx/fleet').json()['devices'][0]['state'] == 'unavailable'


def test_eevx_adb_status_check_returns_without_adb():
    tree = ast.parse(Path('main.py').read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'check_adb_connection')
    fn.decorator_list = []
    env = {'is_eevx_device': lambda _: True}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), 'main.py', 'exec'), env)
    assert env['check_adb_connection']('eevx-' + ID) == (False, 'ADB is not required for Eevx management.')
