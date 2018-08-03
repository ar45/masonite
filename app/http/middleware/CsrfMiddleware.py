""" CSRF Middleware """
from masonite.exceptions import InvalidCSRFToken


class CsrfMiddleware:
    """ Verify CSRF Token Middleware """

    exempt = []

    def __init__(self, Request, Csrf, ViewClass):
        """CRSF Middleware Constructor
        
        Arguments:
            Request {masonite.request.Request} -- The Masonite request object.
            Csrf {masonite.auth.Csrf} -- The Masonite CSRF class
            ViewClass {masonite.view.View} -- The Masonite view object.
        """

        self.request = Request
        self.csrf = Csrf
        self.view = ViewClass

    def before(self):
        """Generate a CRSF token and share to the view
        """

        token = self.__verify_csrf_token()

        self.view.share({
            'csrf_field': "<input type='hidden' name='__token' value='{0}' />".format(token)
            'csrf_token': "{0}".format(token)
        })

    def after(self):
        """Execute code after the route has been executed.
        """
        pass

    def __in_exempt(self):
        """Determine if the request has a URI that should pass
        through CSRF verification.
        """

        if self.request.path in self.exempt:
            return True
        else:
            return False

    def __verify_csrf_token(self):
        """Verify if the csrf token in POST request is valid, else generate a new token.
        """

        if self.request.is_post() and not self.__in_exempt():
            token = self.request.input('__token')
            if not self.csrf.verify_csrf_token(token):
                raise InvalidCSRFToken("Invalid CSRF token.")
        else:
            token = self.csrf.generate_csrf_token()

        return token