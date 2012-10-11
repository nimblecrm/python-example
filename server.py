from json import loads
from os.path import realpath, split, join
from traceback import format_exc
from urllib import urlencode

from tornado.httpclient import HTTPRequest, HTTPClient, HTTPError
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.template import Loader
from tornado.web import RequestHandler, Application

# main application parameters, received from developer portal
_APP_KEY = 'PLACE YOUR APP KEY'
_SECRET_KEY = 'PLACE YOUR APP SECRET'
_PINGBACK_URL = 'YOUR PINGBACK URL'

def _make_slashes(in_str):
    """
    Ensure that in_str starts and ends with single slash
    :param in_str: string to add slashes
    :type in_str: str or unicode
    :return: string with slashes
    :rtype: str or unicode
    """
    return ('/%s/' % in_str).replace('//', '/')

class OurHandler(RequestHandler):
    """
    We have some utility functions, so move them to base class for Request handlers
    """
    @property
    def template_loader(self):
        """
        Return instance of template Loader, loading templates from current <current directory>/templates
        :return: template Loader
        :rtype: Loader
        """
        if not hasattr(self, '_loader'):
            path = split(realpath(__file__))[0]
            tmp_path = join(path, 'templates')
            self._loader = Loader(tmp_path)
        return self._loader

    def make_nimble_request(self, api_path, token, method="GET", **kwargs):
        """
        Make request to existing nimble APIs
        :param api_path: API URL, e.g. api/v1/contacts/list
        :type api_path: str
        :param token: access token
        :type token: str
        :param method: desired HTTP request method
        :type method: str
        :param kwargs: all other request parameters
        :type kwargs: dict
        :return: dict with received data or None on error
        :rtype: dict or NoneType
        """
        try:
            params = kwargs.copy()
            # adding access token to future request
            params['access_token'] = token
            data = urlencode(params)
            path = _make_slashes(api_path)
            url = ''
            # build request
            if method=='GET':
                url = 'https://api.nimble.com%s?%s' % (path, data)
                request = HTTPRequest(url)
            elif method=='POST':
                url = 'https://api.nimble.com%s' % path
                request = HTTPRequest(url)
            else: # if no such method
                raise ValueError('Invalid method %r' % method)

            print('Going to request %s' % url)
            http_client = HTTPClient()
            response = http_client.fetch(request)
            return loads(response.body)
        except HTTPError as ex:
            print('Error %d' % ex.code)
            return None
        except Exception:
            print('Error getting code %s' % format_exc())
            return None


class IndexHandler(OurHandler):
    def get(self, *args, **kwargs):
        """
        Simple main page handler. If we have token, saved in cookie - make request and show result
        If no token - show page, suggesting login
        """
        token = self.get_secure_cookie('nimble_token')
        if token:
            data = self.make_nimble_request('api/v1/contacts/list', token, sort='recently viewed:asc',
                fields='first name,last name')
            if data:
                result = []
                for rec in data.get('resources', []):
                    fields = rec.get('fields', {})
                    fn = fields['first name'][0]['value'] if 'first name' in fields else ''
                    ln = fields['last name'][0]['value'] if 'last name' in fields else ''
                    result.append({'id': rec.get('id'), 'fn': fn, 'ln': ln})
                self.write(self.template_loader.load('result.html').generate(data=result))
        else:
            self.write(self.template_loader.load('index.html').generate(message='No token found, please log in'))


class OAuthHandler(OurHandler):
    def _get_acess_token(self, security_code):
        """
        After OAuth Apigee returns us security code, and to obtain token we need to make additional request
        This function trying to make this request, and return token
        :param security_code: security code, obtained from Apigee
        :type security_code: str
        :return: token on success or None on error
        :rtype: str or NoneType
        """
        try:
            # additional headers to get response as JSON, not as XML
            our_headers = {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            }
            our_params = {
                'client_id': _APP_KEY,
                'code': security_code,
                'grant_type': 'authorization_code',
                'client_secret': _SECRET_KEY,
            }
            request = HTTPRequest('https://api.nimble.com/oauth/token', method='POST', headers=our_headers,
                body=urlencode(our_params))
            http_client = HTTPClient()
            response = http_client.fetch(request)
            if response.code==200:
                data = loads(response.body)
                return data.get('access_token')
            else:
                print('Got incorrect response code %d:\n%s' % (response.code, response.body))
        except HTTPError as ex:
            print('Error %d, message %s' % (ex.code, ex.response.body))
        except Exception:
            print('Error getting code %s' % format_exc())
            return None

    def get(self, *args, **kwargs):
        """
        OAuth handler
        If no additional parameters passed, then it's first call to this handler, we need to redirect user to log in
        page.
        If we receive "error" or "code" parameters - then it's a callback from oauth server, and we're handling this
        situation.
        "code" parameter passed on correct authorisation
        "error" passed on fail
        """
        error = self.get_argument('error', None)
        if error:
            # Apigee sends more verbose description of error in parameter error_description, we're trying to obtain it
            # and show to user
            err_descr = self.get_argument('error_description', None)
            error_msg = err_descr if err_descr is not None else error
            self.write(self.template_loader.load('index.html').generate(message=repr(error_msg)))
            return

        code = self.get_argument('code', None)
        if code:
            # we've got access code, but additional call required to obtain token
            token = self._get_acess_token(code)
            if token is not None:
                self.set_secure_cookie('nimble_token', token)
                self.write(self.template_loader.load('success.html').generate())
                return
            else:
                print('Got no token')
                self.redirect('/')
                return
        # here we process first call to this hanlder. We form redirect url and send user there to authorise
        redirect_url = "https://api.nimble.com/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code" % (
            _APP_KEY, _PINGBACK_URL)
        self.redirect(redirect_url)


class LogoutHandler(OurHandler):
    """
    Handle logout: clear cookie
    """
    def get(self, *args, **kwargs):
        self.clear_all_cookies()
        self.redirect('/')


application = Application([
    (r"/oauth/?", OAuthHandler),
    (r"/logout/?", LogoutHandler),
    (r"/", IndexHandler),
], cookie_secret="k2bJr0E*Hiehuq15PLo6p3SF4>9TBj;c", debug=True) # cookie secret must be good random str

def start_server(port, prefork=True, num_processes=0):
    print("start_server(): starting on port %d, prefork=%s, num_processes=%d" % (port, prefork, num_processes))

    http_server = HTTPServer(application)
    http_server.listen(port)
    IOLoop.instance().start()

if __name__ == '__main__':
    start_server(9000)
