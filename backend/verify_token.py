import os
import json

from six.moves.urllib.request import urlopen
from jose import jwt

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_API_ID = os.environ.get("AUTH0_API_ID")

def verify_token(token):
    # This grabs the public key information and metadata
    jsonurl = urlopen("https://"+AUTH0_DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    # This will get the unverified token header to compare against
    unverified_header = jwt.get_unverified_header(token)
    rsa_key = {}
    for key in jwks["keys"]:
        # Here we compare the public metadata and unverified header
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:  # `decode` is where we do the actual verification
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=AUTH0_API_ID,
                issuer="https://"+AUTH0_DOMAIN+"/"
            )
            print("token validated successfully")
            return payload
        except jwt.ExpiredSignatureError:
            print("Token is expired")
            raise Exception('Unauthorized')
        except jwt.JWTClaimsError:
            print("Token has invalid claims")
            raise Exception('Unauthorized')
        except Exception:
            print("Unable to parse token")
            raise Exception('Unauthorized')
        