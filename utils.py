from starlette import status
from starlette.responses import Response


def check_username(username, response: Response):
        if not user.username.isalpha():
            response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'username must be alphabetical characters'}, status.HTTP_400_BAD_REQUEST

    if len(user.username) < 4 or len(user.username) > 32:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'length of user name must be between 4,32'}


def check_password(password, response: Response):
    if len(password) < 8:
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'length of password must be more than 8 char'}

    if not password.isalnum():
        response.status_code = status.HTTP_400_BAD_REQUEST
        return {'error': 'password should contain number and alphabetical characters'}

