import json
from flask import request 
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'udacity-fsnd.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'dev'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header


def get_token_auth_header():
   
    # Get the header from the request
    auth_header = request.headers.get('Authorization', None)

    # Raise an AuthError if no header is present
    if not auth_header:
        raise AuthError({
            'code': 'authorization_header_missing',
            'description': 'Authorization header is expected.'
        }, 401)

    # Split bearer and the token
    parts = auth_header.split()

    # Raise an AuthError if the header is malformed
    if parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with "Bearer".'
        }, 401)

    # Raise an AuthError if token is not found
    elif len(parts) == 1:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Token not found.'
        }, 401)

    # Raise an AuthError if the header is malformed (contains more than bearer and token)
    elif len(parts) > 2:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be bearer token.'
        }, 401)

    # Extract and return the token part of the header
    token = parts[1]
    return token


def check_permissions(permission, payload):

    # Check if 'permissions' key is present in the payload
    if 'permissions' not in payload:
        # Raise an AuthError if permissions are not included in JWT
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Permissions not included in JWT.'
        }, 400)

    # Check if the required permission is present in the list of permissions
    if permission not in payload['permissions']:
        # Raise an AuthError if the required permission is not found
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission not found.'
        }, 403)

    # Return True if the permission is found
    return True

def verify_decode_jwt(token):

    # Retrieve JSON Web Key Set (JWKS) from Auth0
    jsonurl = urlopen(f'https://fullstacklamya.us.auth0.com/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Get the unverified header of the JWT token
    unverified_header = jwt.get_unverified_header(token)

    rsa_key = {}

    # Raise an AuthError if 'kid' is not present in the unverified header
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed.'
        }, 401)

    # Find the appropriate RSA key in the JWKS based on the 'kid' from the unverified header
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }

    # Raise an AuthError if the appropriate key is not found
    if not rsa_key:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to find the appropriate key.'
        }, 400)

    try:
        # Use the key to validate and decode the JWT
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer='https://' + AUTH0_DOMAIN + '/'
        )

        return payload

    except jwt.ExpiredSignatureError:
        # Raise an AuthError if the token has expired
        raise AuthError({
            'code': 'token_expired',
            'description': 'Token expired.'
        }, 401)

    except jwt.JWTClaimsError:
        # Raise an AuthError if the token contains incorrect claims
        raise AuthError({
            'code': 'invalid_claims',
            'description': 'Incorrect claims. Please, check the audience and issuer.'
        }, 401)

    except Exception:
        # Raise an AuthError if there is an issue parsing the authentication token
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Unable to parse authentication token.'
        }, 400)


def requires_auth(permission=''):

    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Get the JWT token from the Authorization header
            token = get_token_auth_header()

            try:
                # Verify and decode the JWT token
                payload = verify_decode_jwt(token)
            except:
                # Raise an AuthError if the token is invalid
                raise AuthError({
                    'code': 'invalid_token',
                    'description': 'Access denied due to invalid token'
                }, 401)

            # Check if the required permission is present in the payload
            check_permissions(permission, payload)

            # Call the original function with the decoded payload
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
