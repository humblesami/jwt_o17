# JWT Authentication for Odoo Controllers

This module adds JWT authentication to Odoo APIs, providing a stateless authentication mechanism suitable for mobile and server-based applications.
After installation just go to `https://localhost:8069/api/login` and you can use and understand all the functionality

## Features

- **Authentication Routes**: `/api/authenticate` for login, `/api/update/access-token` and `/api/update/refresh-token` for token management, and `/api/revoke/token` for logout.
- **Protected Resources**: Access endpoints like `/api/protected/json` with valid JWT tokens.

## Why JWT?

JWTs offer a stateless authentication method that doesn't rely on server-stored sessions, making them ideal for mobile and server-based applications. They reduce server overhead and improve scalability by embedding authentication data within the token itself.

## Installation

1. Install PyJWT: `pip install PyJWT`
2. This module is compatible with Odoo 11 and later versions, including Odoo 17.

For detailed installation guides:
- [Video Tutorial](https://www.youtube.com/watch?v=coQzKW6l_y8)
- [Text Guide](https://www.cybrosys.com/blog/how-to-install-custom-modules-in-odoo)

## Module Documentation

### irHttp (models.AbstractModel) (models/ir_http.py)

Overrides `_authenticate` to handle JWT authentication by checking the Authorization header and validating the token.

### JwtToken (setup/jwt_token.py)

- **`get_jwt_secret(cls)`**: Retrieves the secret key for token signing.
- **`generate_token(cls, user_id, duration=0)`**: Generates a JWT token for a user.
- **`create_refresh_token(cls, uid)`**: Creates and stores a refresh token; sets it as a secure cookie for web clients.
- **`verify_refresh_token(cls, req, uid, r_token)`**: Validates the refresh token.

### ApiAuth (http.Controller) (controllers/api_uth.py)

**Endpoints:**

- **`/api/authenticate`**: Authenticates a user and issues tokens.
  - **Input**: `{ "db": "o17e", "login": "admin", "password": "xxx" }`
  - **Output**: `{ 'rotation_period': n, 'token': xxx, 'user_id': xx, ... }`

- **`/api/update/access-token`**: Refreshes an access token.
  - **Input**: `{ 'user_id': xx }`
  - **Headers (mobile)**: `{'refreshToken': xx, ...default_headers}`
  - **Output**: `{ 'access_token': xxx }`

- **`/api/update/refresh-token`**: Rotates the refresh token.
  - **Input**: `{ 'user_id': xx }`
  - **Headers (mobile)**: `{'refreshToken': xxxx, ...default_headers}`
  - **Output**: `{ 'status': 'done' }`

- **`/api/revoke/token`**: Revokes a refresh token.
  - **Input**: `{}`  
  - **Headers (mobile)**: `{'refreshToken': xxxx, ...default_headers}`
  - **Output**: `{ 'status': 'done' }`

- **`/api/protected/json`**: Access protected resources with a valid JWT.
  - **Input**: `{}`  
  - **Headers (mobile)**: `{'refreshToken': xxxx, ...default_headers}`
  - **Output**: `{ 'status': user_list }`

### Utility Methods

- **`get_refresh_token(cls, req_obj)`**: Retrieves the refresh token from cookies or headers.
- **`get_json_params(cls)`**: Extracts JSON parameters from the request body.

## Testing

Use the `/api/login` page to test API routes by entering host details, API URL, headers, and input data.

## Notes

```
default_headers = { 
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'access_token': xxx (null in case of /api/authenticate and /api/update/access-token)
}
```

**Secret key** auto created on module install. Its added it gitignore, you can however update the key manually after install  

For best performance, on token revoke (logout) the long term token (refreshToken is marked as is_revoked and no more usable)
but the access token which has no direct relation to the refreshToken will be valid until its expiry time reaches (60 seconds total), s
o it has been left upon client to discard the access_token on logout, so server has not to make any extra checks for token validation

This module is designed for seamless JWT integration with Odoo APIs, enhancing security and scalability for your applications.

[//]: # ()