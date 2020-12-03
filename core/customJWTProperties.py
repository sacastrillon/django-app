from rest_framework_simplejwt.authentication import JWTAuthentication

class CustomAuthentication(JWTAuthentication):
    def get_raw_token(self, header):
        """
        Extracts an unvalidated JSON web token from the given "Authorization"
        header value.
        """
        parts = header.split()

        if len(parts) == 0:
            # Empty AUTHORIZATION header sent
            return None

        if len(parts) == 1:
            return parts[0]