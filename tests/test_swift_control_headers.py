# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@chmouel.com>"
import unittest

import swift_control_headers.middleware as middleware

from swift.common.swob import Response, Request


class FakeApp(object):
    def __init__(self, status_headers_body=None):
        self.status_headers_body = status_headers_body
        if not self.status_headers_body:
            self.status_headers_body = ('204 No Content', {}, '')

    def __call__(self, env, start_response):
        req = Request(env)
        status, headers, body = self.status_headers_body
        if req.method == 'GET':
            headers = req.headers
        return Response(status=status, headers=headers,
                        body=body)(env, start_response)


class TestSwiftControlHeaders(unittest.TestCase):
    def _make_request(self, **kwargs):
        req = Request.blank("/v1/AUTH_account/cont", **kwargs)
        return req

    def setUp(self):
        self.conf = {
            'header_h1': 'acc:usr=r',
            'header_h2': '*=-',
            'header_h3': 'admin:admin=rw',
            'header_h4': 'admin:admin=rw,acc:foo=-,*=-',
            'header_h5': 'acc:usr=r,*=-',
            'header_h6': 'acc:usr=rw,*=-'}
        self.test_default = middleware.filter_factory(self.conf)(FakeApp())

    def test_allowed_to_write_default(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('acc', 'foo'),
                     },
            headers={'X-Container-Meta-Unkown':  'newvalue'})

        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_allowed_to_write(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('acc', 'usr'),
                     },
            headers={'X-Container-Meta-h3':  'newvalue'})

        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_keystone_identitiy_allowed_to_write(self):
        headers = {'X-Container-Meta-h6': 'newvalue'}

        req = self._make_request(
            environ={
                'REQUEST_METHOD': 'POST',
                'REMOTE_USER': ('shouldfail', 'weusekeystone'),
                'keystone.identity': {
                    'tenant': (1, 'acc'),
                    'user': 'usr',
                }
            },
            headers=headers)
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

    def test_allowed_denied_same_header(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('admin', 'admin'),
                     },
            headers={'X-Container-Meta-h4':  'newvalue'})
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' not in resp.environ)

        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('id', 'foo'),
                     },
            headers={'X-Container-Meta-h4':  'newvalue'})
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' in resp.environ)

    def test_denied_to_write_star(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('id', 'admin'),
                     },
            headers={'X-Container-Meta-h2':  'newvalue'})
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' in resp.environ)

    def test_denied_to_write(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'POST',
                     'REMOTE_USER': ('acc', 'usr'),
                     },
            headers={'X-Container-Meta-h1':  'newvalue'})
        resp = req.get_response(self.test_default)
        self.assertTrue('swift.authorize' in resp.environ)

    def test_allowed_to_read_default(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'GET',
                     'REMOTE_USER': ('acc', 'usr'),
                     },
            headers={'X-Container-Meta-foo':  'newvalue'})
        resp = req.get_response(self.test_default)
        self.assertTrue('HTTP_X_CONTAINER_META_FOO' in resp.environ)

    def test_allowed_to_read(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'GET',
                     'REMOTE_USER': ('acc', 'usr'),
                     },
            headers={'X-Container-Meta-foo':  'newvalue'})
        test_middleware = middleware.ControlHeaderMiddleware(FakeApp,
                                                             self.conf)
        newheaders = test_middleware.process_read_request(req,
                                                          req.headers.items())
        self.assertTrue('X-Container-Meta-Foo' in dict(newheaders))

    def test_denied_to_read(self):
        req = self._make_request(
            environ={'REQUEST_METHOD': 'GET',
                     'REMOTE_USER': ('acc', 'usr'),
                     },
            headers={'X-Container-Meta-h2':  'newvalue'})
        test_middleware = middleware.ControlHeaderMiddleware(FakeApp,
                                                             self.conf)
        newheaders = test_middleware.process_read_request(req,
                                                          req.headers.items())
        self.assertFalse('X-Container-Meta-h2' in dict(newheaders))
