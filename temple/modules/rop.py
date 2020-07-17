import argparse
import utils
import os
template_path = os.path.join(os.path.dirname(__file__), "../templates/rop.temple.py")

class RopTemplater:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('binary')
        parser.add_argument('--remote-url', default=':0')
        parser.add_argument('--remote-libc')

        self._parser = parser

    def parse_args(self, args):
        argp = self._parser.parse_args(args)
        self.binary = argp.binary
        self.remote_host, self.remote_port = argp.remote_url.split(':')
        self.libc = None if argp.remote_libc is None else {'REMOTE': argp.remote_libc, 'LOCAL': '/lib32/libc.so.6'}

    def template_args(self):
        overflow = utils.find_overflow(self.binary)
        return {
            'binary': self.binary,
            'remote_host': self.remote_host,
            'remote_port': self.remote_port,
            'libc':        self.libc,
            'overflow': overflow
        }

    @property
    def template(self):
        return template_path
