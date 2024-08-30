from odoo import api
from odoo.tests import TransactionCase
from ..controllers.api_uth import ApiAuth

class TestApiAuth(TransactionCase):

    def setUp(self):
        super().setUp()
        # Create a test user for authentication
        self.test_user = self.env['res.users'].create({
            'name': 'Test User',
            'login': 'test_user',
            'password': 'test_password',
        })

    def test_authenticate_post_success(self):
        """Test successful authentication with valid credentials."""
        data = {'login': self.test_user.login, 'password': 'test_password'}
        response = self.web_client.post('/api/authenticate', data=data)
        self.assertEqual(response.status_code, 200, "Authentication failed")
        self.assertIn('access_token', response.json())
        self.assertIn('user_id', response.json())
        self.assertEqual(response.json()['user_id'], self.test_user.id)

    def test_authenticate_post_missing_credentials(self):
        """Test authentication failure with missing credentials."""
        data = {'login': ''}  # Missing password
        response = self.web_client.post('/api/authenticate', data=data)
        self.assertEqual(response.status_code, 400, "Authentication should fail with missing credentials")
        self.assertIn('error', response.json())
        self.assertEqual(response.json()['error'], "Please provide login and password")

        data = {'password': 'test_password'}  # Missing login
        response = self.web_client.post('/api/authenticate', data=data)
        self.assertEqual(response.status_code, 400, "Authentication should fail with missing credentials")
        self.assertIn('error', response.json())
        self.assertEqual(response.json()['error'], "Please provide login and password")

    def test_authenticate_post_invalid_credentials(self):
        """Test authentication failure with invalid credentials."""
        data = {'login': 'invalid_user', 'password': 'wrong_password'}
        response = self.web_client.post('/api/authenticate', data=data)
        self.assertEqual(response.status_code, 400, "Authentication should fail with invalid credentials")
        self.assertIn('error', response.json())
        self.assertEqual(response.json()['error'], "Invalid login or password")

    def test_revoke_api_token(self):
        """Test successful revocation of refresh token."""
        # This test requires authentication for obtaining a token. Implement the logic to first authenticate and obtain a token
        # Then, set the token in headers or cookies and call revoke_api_token
        # self.assertTrue(False, "Implement authentication and token retrieval logic first")

        # Uncomment and modify the following code after implementing authentication
        # data = {'user_id': self.test_user.id}  # Assuming you have a valid token
        # response = self.web_client.post('/api/revoke/token', data=data)
        # self.assertEqual(response.status_code, 200, "Failed to revoke refresh token")
        # self.assertEqual(response.json()['status'], 'success')

    def test_updated_short_term_token(self):
        """Test successful retrieval of a new access token using a valid refresh token."""
        # This test requires authentication for obtaining a token. Implement the logic to first authenticate and obtain a token
        # Then, set the token in headers or cookies and call updated_short_term_token
        # self.assertTrue(False, "Implement authentication and token retrieval logic first")

        # Uncomment and modify the following code after implementing authentication
        # data = {'user_id': self.test_user.id}  # Assuming you have a valid token
        # response = self.web_client.post('/api/update/access-token', data=data)
        # self.