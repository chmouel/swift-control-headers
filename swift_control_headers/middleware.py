# -*- encoding: utf-8 -*-
__author__ = "Chmouel Boudjnah <chmouel@chmouel.com>"
from swift.common.utils import get_logger
from swift.common.swob import HTTPForbidden, Request


class DenyHeaderWriteNotPermitted(Exception):
    pass


class ControlHeaderMiddleware(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf

        self.logger = get_logger(self.conf, log_route='control_headers')

        self.config = {}
        for conf_key in conf:
            if not conf_key.startswith("header_"):
                continue
            v = conf_key.replace('header_', '').replace('-', '_')
            self.config[v] = {}
            for row in conf[conf_key].split(','):
                user, perm = row.split("=")
                if ':' in user:
                    user = tuple(user.split(':'))
                self.config[v][user] = perm

    def process_write_request(self, req):
        for header in req.headers:
            if not '-Meta-' in header:
                continue
            _header = header[header.find("-Meta-") + 6:]
            _header = _header.replace('-', '_').lower()
            user = req.remote_user

            if not _header in self.config:
                continue

            if (user in self.config[_header] and
                    self.config[_header][user] == "rw"):
                continue

            if (user in self.config[_header] and
                self.config[_header][user] in ("-", "r")) or \
                ('*' in self.config[_header] and
                 self.config[_header]['*'] in ("-", "r")):
                self.logger.debug(
                    "[control_headers] Forbidding writing %s header for %s" %
                    (_header, user))
                raise DenyHeaderWriteNotPermitted

    def process_read_request(self, req, headers):
        newheaders = []
        for header in headers:
            h = header[0].lower()
            if not '-meta-' in h:
                newheaders.append(header)
                continue
            _header = h[h.find("-meta-") + 6:]
            _header = _header.replace('-', '_')
            if _header in self.config:
                user = req.remote_user
                if (user in self.config[_header] and
                    self.config[_header][user] == "-") or \
                    ('*' in self.config[_header] and
                     self.config[_header]['*'] == "-"):
                    self.logger.debug(
                        "[control_headers] Skip showing %s header" %
                        (_header))
                    continue
                # Default to show this may change (and due duplication).
                newheaders.append(header)
            else:
                newheaders.append(header)

        return newheaders

    def deny(self, req):
        return HTTPForbidden(request=req)

    def __call__(self, env, start_response):
        req = Request(env)

        if req.method in ("POST", "PUT"):
            try:
                self.process_write_request(req)
            except(DenyHeaderWriteNotPermitted):
                env['swift.authorize'] = self.deny
            return self.app(env, start_response)

        def replace_start_response(status, headers, exc_info=None):
            newheaders = self.process_read_request(req, headers)
            start_response(status, newheaders, exc_info)

        return self.app(env, replace_start_response)


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    return lambda app: ControlHeaderMiddleware(app, conf)
