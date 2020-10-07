"""AuthCookieDriver Module."""
import json
from datetime import datetime, timedelta

from cryptography.fernet import InvalidToken

from ...contracts import AuthContract
from ...drivers import BaseDriver
from ...request import Request
from ...auth.Sign import Sign


class AuthCookieDriver(BaseDriver, AuthContract):
    def __init__(self, request: Request):
        """AuthCookieDriver initializer.

        Arguments:
            request {masonite.request.Request} -- The Masonite request class.
        """
        self.request = request

    def user(self, auth_model):
        """Gets the user based on this driver implementation

        Arguments:
            auth_model {orator.orm.Model} -- An Orator ORM type object.

        Returns:
            Model|bool
        """
        token = self.request.get_cookie("token")
        if token and auth_model:
            try:
                decrypted = Sign().unsign(token)
            except InvalidToken:
                return False
            decrypted = json.loads(decrypted)
            # print(decrypted)
            expires = decrypted.get('expires')
            if expires:
                expires = datetime.fromisoformat(expires)
            if not expires or expires <= datetime.now():
                # print('session expired {}'.format(expires))
                return False
            assert decrypted.get('id')
            return auth_model.where(
                "id", decrypted.get('id')
            ).first()

        return False

    def save(self, model=None):
        """Saves the cookie to some state.

        In this case the state is saving to a cookie.

        Arguments:
            remember_token {string} -- A token containing the state.

        Returns:
            bool
        """
        data = model.serialize()
        data.pop('password', None)
        data['iat'] = datetime.now()
        data['expires'] = datetime.now() + timedelta(minutes=60)
        encrypted = Sign().sign(json.dumps(data, default=str))
        return self.request.cookie("token", encrypted)

    def delete(self):
        """Deletes the state depending on the implementation of this driver.

        Returns:
            bool
        """
        return self.request.delete_cookie("token")

    def logout(self):
        """Deletes the state depending on the implementation of this driver.

        Returns:
            bool
        """
        self.delete()
        self.request.reset_user()
