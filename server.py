#!/usr/bin/env python
#
# Copyright 2012 Nimble
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

import logging
import os.path
from urllib import urlencode

import tornado.auth
import tornado.escape
import tornado.gen
import tornado.httpclient
import tornado.httpserver
import tornado.ioloop
import tornado.options
import tornado.web
from tornado.options import define, options


define("port", default=9000, help="run on the given port", type=int)
define("nimble_api_key", help="your Nimble application API key",
    default="4550f11d2af4f3d74349767a552b4859")
define("nimble_secret", help="your Nimble application secret",
    default="1ea5c1ddc6f020b9")
define("redirect_url", help="redirect URL of your app",
    default="http://localhost:9000/oauth/login")

##### Nimble-specific classes
class NimbleHandler(tornado.web.RequestHandler, tornado.auth.OAuth2Mixin):
    """
    Nimble's custom OAuth2 handler for authenticating users with their Nimble accounts and receiving tokens
    """
    _OAUTH_ACCESS_TOKEN_URL = "https://api.nimble.com/oauth/token?"
    _OAUTH_AUTHORIZE_URL = "https://api.nimble.com/oauth/authorize?"
    _OAUTH_REQUEST_URL = "https://api.nimble.com/"

    @tornado.gen.engine
    def get_authenticated_user(self, callback):
        """
        Handle redirect from Nimble after successful OAuth
        """
        code = self.get_argument("code", None)
        if not code:                                # if no code supplied
            logging.warning('Got no key')
            callback(None)

        # make a request to obtain token by code
        http = tornado.httpclient.AsyncHTTPClient()
        req_url = self._oauth_request_token_url(client_id=self.settings["nimble_api_key"], code=code,
            client_secret=self.settings["nimble_secret"], extra_params={"grant_type": "authorization_code"})
        our_headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        }
        request = tornado.httpclient.HTTPRequest(
            req_url, headers=our_headers,
        )
        # fetch token
        response = yield tornado.gen.Task(http.fetch, request)
        if response.error:
            logging.warning("Error response %s fetching %s", response.error, response.request.url)
            callback(None)
            return

        token = tornado.escape.json_decode(response.body) if response else None

        if token is None:
            logging.warning("access_token is broken")
            callback(None)
            return

        # Make request to API to get current logged user info, using freshly-obtained token.
        # NB: this API call well be changed in future
        self.nimble_request((yield tornado.gen.Callback("get-user-data")), u"/api/users/myself/",
            access_token=token['access_token'])
        user_data = yield tornado.gen.Wait("get-user-data")
        if user_data:
            token.update(user_data)

        callback(token)

    @tornado.gen.engine
    def nimble_request(self, callback, api_path, method=u'GET', access_token=None, body=None, **kwargs):
        """
        Make async request to Nimble API
        :param callback: callback to pass results
        :type callback: func
        :param api_path: path to required API
        :type api_path: unicode
        :param method: HTTP method to use, default - GET
        :type method: unicode
        :param access_token: API access token, if passed explicitly. If this parameter is omitted - function will try
            to get token from currently logged user info
        :type access_token: str or unicode
        :param body: HTTP request body for POST request, default - None
        :type body: str or NoneType
        :return: None
        :rtype: NoneType
        """
        if access_token is None:
            user = self.get_current_user()
            if isinstance(user, dict) and 'access_token' in user:
                access_token = user['access_token']
            else:
                logging.warning("Access token required")
                callback(None)
                return

        args = {"access_token": access_token}

        if kwargs:
            args.update(kwargs)

        url = 'https://api.nimble.com%s?%s' % (api_path, urlencode(args))
        request = tornado.httpclient.HTTPRequest(url, method, body=body)

        http = tornado.httpclient.AsyncHTTPClient()
        response = yield tornado.gen.Task(http.fetch, request)

        if response.error:
            logging.warning("Error response %s fetching %s", response.error, response.request.url)
            callback(None)
            return
        data = tornado.escape.json_decode(response.body) if response else None
        callback(data)

    def get_current_user(self):
        """
        Get current user info, by default stored in "nimble_user" secure cookie
        """
        user_json = self.get_secure_cookie("nimble_user")
        if not user_json: return None
        return tornado.escape.json_decode(user_json)


class NimbleLoginHandler(NimbleHandler):
    """
    Handler for OAuth login
    """
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        # if we got "code" parameter, then it's callback from Nimble OAuth server
        # get user data and store it
        if self.get_argument("code", None):
            user = yield tornado.gen.Task(self.get_authenticated_user)
            # store login user data
            self.set_secure_cookie("nimble_user", tornado.escape.json_encode(user))
            if not user:
                raise tornado.web.HTTPError(500, "Nimble auth failed")
            self.redirect("/")
        # if we need to handle OAuth errors, here we should check for "error" command line parameter
        else:
        # it's first call to handler, or we got error - redirect user back to Nimble API
            self.authorize_redirect(redirect_uri=self.settings["redirect_url"],
                client_id=self.settings["nimble_api_key"],
                extra_params={"response_type": "code", "scope": "testApp"})


class NimbleLogoutHandler(tornado.web.RequestHandler):
    """
    Handler for OAuth log out
    """
    def get(self):
        self.clear_cookie("nimble_user")
        self.write('You are now logged out. '
                   'Click <a href="/">here</a> to log back in.')


class Application(tornado.web.Application):
    """
    Basic class for sample application with configuration
    """
    def __init__(self):
        handlers = [
            (r"/", MainHandler),
            (r"/oauth/login/?", NimbleLoginHandler),
            (r"/oauth/logout/?", NimbleLogoutHandler),
            ]
        settings = {
            "cookie_secret": "k2bJr0E*Hiehuq15PLo6p3SF4>9TBj;c", # fairly random string, generate yours for usage
            "login_url": "/oauth/login",
            "template_path": os.path.join(os.path.dirname(__file__), "templates"),
            "static_path": os.path.join(os.path.dirname(__file__), "static"),
            "xsrf_cookies": True,
            "nimble_api_key": options.nimble_api_key,  # three values below should be set
            "nimble_secret": options.nimble_secret,
            "redirect_url": options.redirect_url,
            "debug": True,
            "autoescape": None,
            }
        tornado.web.Application.__init__(self, handlers, **settings)


class MainHandler(NimbleHandler):
    """
    Small example of usage for classes above: log in via Nimble and get recently viewed contacts
    """
    @tornado.web.authenticated
    @tornado.web.asynchronous
    @tornado.gen.engine
    def get(self):
        # get recently viewed data
        # usage of tornado.gen - greatly simplifies chains of async calls
        self.nimble_request((yield tornado.gen.Callback("get-recently-viewed")),
                            u'/api/v1/contacts/list', sort=u'recently viewed:asc', fields=u'first name,last name')

        data = yield tornado.gen.Wait("get-recently-viewed")
        # get user name to show in template
        name = tornado.escape.xhtml_escape(self.current_user['name'])
        result = []
        # parse data, received from Nimble
        if data:
            for rec in data.get('resources', []):
                fields = rec.get('fields', {})
                fn = fields['first name'][0]['value'] if 'first name' in fields else ''
                ln = fields['last name'][0]['value'] if 'last name' in fields else ''
                result.append({'id': rec.get('id'), 'fn': fn, 'ln': ln})

        self.render('result.html', user=name, data=result)


def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()