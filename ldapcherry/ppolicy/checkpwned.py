# -*- coding: utf-8 -*-
# vim:set expandtab tabstop=4 shiftwidth=4:
#
# The MIT License (MIT)
# LdapCherry
# Copyright (c) 2014 Carpentier Pierre-Francois

import ldapcherry.ppolicy
import re
import requests
from hashlib import sha1

class PPolicy(ldapcherry.ppolicy.PPolicy):

    def __init__(self, config, logger):
        self.config = config
        self.api_url = self.get_param('api_url', 'https://api.pwnedpasswords.com/range/').rstrip('/')
        self.api_prefix_len = self.get_param('api_prefix_len', 5)
        self.session = requests.Session()
        self.session.headers.update({
            'user-agent': 'ldapcherry-ppolicy-checkpwned/0.1 ' + self.session.headers['User-Agent'],
            'accept': 'text/plain'
        })


    def check(self, password):
        digest = sha1(bytes(password, 'utf8')).hexdigest().upper()
        prefix = digest[:self.api_prefix_len]
        suffix = digest[self.api_prefix_len:]
        r = self.session.get(self.api_url + '/' + prefix)
        if r.status_code == requests.codes.ok:
            for line in r.text.split('\r\n'):
                match, sep, n = line.partition(':')
                if match == suffix:
                    return {'match': False, 'reason': 'This password has been breached {} times'.format(n)}
            return {'match': True, 'reason': 'password ok'}
        else:
            raise Exception('error reaching pwned service')

    def info(self):
        return "* checks securely against the database at https://haveibeenpwned.com/"

