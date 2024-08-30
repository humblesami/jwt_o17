import requests
from odoo import http
from odoo.http import request


class SampleClientController(http.Controller):

    @http.route('/api/test', type='json', auth="none")
    def test_api(self):
        req = request
        http_req = req.httprequest
        params = {}
        if hasattr(http_req, 'json'):
            params = http_req.json or {}
        if not (len(params.keys())):
            if hasattr(req, 'params'):
                params = req.params or {}
        input_data = params.get('input_data')
        input_data['db'] = params['db']
        api_url = params['host'] + params['url']
        auth = params.get('Authorization')
        headers = {'Authorization': auth, 'refreshToken': params.get('refreshToken')}
        resp = requests.post(api_url, headers=headers, timeout=600, json=input_data)
        api_data = resp.json()
        if api_data.get('result'):
            r_token = api_data.get('result').get('refreshToken')
            if r_token:
                res_data = api_data.get('result')
                pf = req.httprequest.user_agent.platform or ''
                pf = pf.lower()
                if not pf:
                    res_data['refreshToken'] = r_token
                elif pf == 'ios' or pf == 'ios':
                    res_data['refreshToken'] = r_token
                else:
                    req.future_response.set_cookie('refreshToken', r_token, httponly=True, secure=True, samesite='Lax')
        if not api_data.get('error'):
            api_data = api_data['result']
        return api_data

    @http.route('/api/login', type='http', auth='public')
    def api_login_page(self, **kwargs):
        db_name = request.db or request.session.db
        html_content = '''<div>Sami</div>'''
        context = {'form': {'db': db_name or ''}}
        # return request.make_response(html_content, [('Content-Type', 'text/html')])
        return request.render('odoo_jwt.LoginTemplate', context)

    @http.route('/api/template', type='http', auth="none")
    def test_template(self):
        context = {}
        return request.render('odoo_jwt.ApiTestTemplate', context)

