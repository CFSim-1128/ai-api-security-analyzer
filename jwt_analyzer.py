import jwt
from jwt import InvalidTokenError


class JWTAnalyzer:
    def analyze(self, token: str) -> dict:
        result = {
            "valid_structure": False,
            "header": {},
            "payload": {},
            "issues": []
        }

        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})

            result["valid_structure"] = True
            result["header"] = header
            result["payload"] = payload

            alg = str(header.get("alg", "")).lower()
            if alg in {"none", "null", ""}:
                result["issues"].append("JWT uses insecure or missing algorithm")

            if "exp" not in payload:
                result["issues"].append("Missing exp claim")

            if "iat" not in payload:
                result["issues"].append("Missing iat claim")

            if "sub" not in payload:
                result["issues"].append("Missing sub claim")

            if "aud" not in payload:
                result["issues"].append("Missing aud claim")

        except InvalidTokenError:
            result["issues"].append("Invalid JWT format or signature structure")
        except Exception as e:
            result["issues"].append(f"JWT parsing error: {str(e)}")

        return result