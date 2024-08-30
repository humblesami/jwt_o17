from odoo.tests import HttpCase, tagged
import json

@tagged('post_install', '-at_install')
class TestApiAuth(HttpCase):

    def setUp(self):
        super(TestApiAuth, self).setUp()
        # Common setup for your tests
        self.db_name = self.env.cr.dbname
        self.login = 'admin'
        self.password = 'admin'

    def test_authenticate_post(self):
        # Test case for /api/authenticate
        # Valid credentials
        response = self.url_open(
            '/api/authenticate',
            json.dumps({'login': self.login, 'password': self.password, 'db': self.db_name}),
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('token', data)

        # Missing credentials
        response = self.url_open(
            '/api/authenticate',
            json.dumps({}),
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['error'], "Please provide login and password")

    def test_revoke_api_token(self):
        # Test case for /api/revoke/token
        response = self.url_open(
            '/api/revoke/token',
            json.dumps({'user_id': 1}),
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')

    def test_updated_short_term_token(self):
        # Test case for /api/update/access-token
        response = self.url_open(
            '/api/update/access-token',
            json.dumps({'user_id': 1}),
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('access_token', data)

    def test_updated_long_term_token(self):
        # Test case for /api/update/refresh-token
        response = self.url_open(
            '/api/update/refresh-token',
            json.dumps({'user_id': 1}),
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'done')
        self.assertIn('refreshToken', data)

    def test_protected_users_json(self):
        # Test case for /api/protected/test
        response = self.url_open(
            '/api/protected/test',
            headers={'Content-Type': 'application/json'}
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('data', data)
        self.assertIsInstance(data['data'], list)
        self.assertIn('uid', data)

