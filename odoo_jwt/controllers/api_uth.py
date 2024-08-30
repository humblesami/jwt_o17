from odoo import http
from odoo.http import request
from ..setup.jwt_token import JwtToken


class ApiAuth(http.Controller):

    @http.route('/api/authenticate', type='json', auth='none', methods=['POST'], csrf=False)
    def authenticate_post(self, **kwargs):
        params = self.__class__.get_json_params()
        login = params.get('login')
        password = params.get('password')
        db_name = request.db or params.get('db') or request.session.db
        if not login or not password:
            return {"error": "Please provide login and password"}
        try:
            uid = request.session.authenticate(db_name, login, password)
            if not uid:
                return {"error": "Invalid login or password"}
        except:
            return {"error": "Invalid login or password"}
        try:
            access_token = JwtToken.generate_token(uid)
            refresh_token = JwtToken.create_refresh_token(request, uid)
            rotation_period = JwtToken.REFRESH_TOKEN_SECONDS * 3/4
            res_data = {
                'rotation_period': rotation_period,
                'token': access_token, 'user_id': uid,
                'long_term_token_span': JwtToken.REFRESH_TOKEN_SECONDS,
                'short_term_token_span': JwtToken.ACCESS_TOKEN_SECONDS,
            }
            is_browser = request.httprequest.user_agent.browser
            if not is_browser:
                res_data['refreshToken'] = refresh_token
            return res_data
        except Exception as exc:
            return {"error": str(exc)}

    @http.route('/api/update/access-token', type='json', auth='none', csrf=False)
    def updated_short_term_token(self, **kwargs):
        params = self.__class__.get_json_params()
        if not params.get('user_id'):
            return {'error': 'User id not given'}
        user_id = int(params.get('user_id'))
        long_term_token = self.__class__.get_refresh_token(request)
        JwtToken.varify_refresh_token(request, user_id, long_term_token)
        new_token = JwtToken.generate_token(user_id)
        return {'access_token': new_token }

    # will be called after for rotation of long term refresh-tokens from client (if rotation_period>=0)
    @http.route('/api/update/refresh-token', type='json', auth='jwt', methods=['POST'], csrf=False)
    def updated_long_term_token(self, **kwargs):
        params = self.__class__.get_json_params()
        user_id = params.get('user_id')
        user_id = int(user_id)
        old_token = self.get_refresh_token(request)
        JwtToken.varify_refresh_token(request, user_id, old_token)
        new_token = JwtToken.create_refresh_token(request, user_id)
        res_data = {'status': 'done'}
        is_browser = request.httprequest.user_agent.browser
        if not is_browser:
            res_data['refreshToken'] = new_token
        else:
            res_data['refreshToken'] = 1
            request.future_response.set_cookie('refreshToken', new_token, httponly=True, secure=True, samesite='Lax')
        return res_data

    @http.route('/api/revoke/token', type='json', auth='jwt', methods=['POST'], csrf=False)
    def revoke_api_token(self, **kwargs):
        params = self.__class__.get_json_params()
        user_id = params.get('user_id')
        user_id = int(user_id)
        tok_ob = request.env['jwt.refresh_token'].sudo().search([('user_id', '=', user_id)])
        # will update the access token, so will become inaccessible immediately
        long_term_token = self.get_refresh_token(request)
        JwtToken.varify_refresh_token(request, user_id, long_term_token)
        tok_ob.is_revoked = True
        return {'status': 'success', 'logged_out': 1}

    @http.route('/api/protected/test', type='json', auth='jwt', methods=['POST'], csrf=False)
    def protected_users_json(self):
        uob = request.env.user
        users = [{'id': 1, 'name': 'sami3'}]
        user_data = [{'id': user['id'], 'name': user['name']} for user in users]
        return {'uid': uob.id, 'data': user_data}

    @classmethod
    def get_refresh_token(cls, req_obj):
        key_name = 'refreshToken'
        http_req = req_obj.httprequest
        long_term_token = http_req.cookies.get(key_name)
        if not long_term_token:
            long_term_token = http_req.headers.get(key_name)
        return long_term_token

    @classmethod
    def get_json_params(cls):
        http_req = request.httprequest
        params = {}
        if hasattr(http_req, 'json'):
            params = http_req.json or {}
        if not (len(params.keys())):
            if hasattr(request, 'params'):
                params = request.params or {}
        return params
