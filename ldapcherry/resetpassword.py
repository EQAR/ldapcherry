# -*- coding: utf-8 -*-
# vim:set expandtab tabstop=4 shiftwidth=4:
#
# Copyright (c) 2020 Colin Tück

import cherrypy
import threading
import subprocess
import logging

from secrets import token_urlsafe
from hashlib import sha512
from datetime import datetime, timedelta
from email.message import EmailMessage

from cherrypy.process import plugins
from ldapcherry.exceptions import UserDoesntExist, InvalidToken

TOKEN_BYTES = 48
TOKEN_MINUTES = 60
GC_INTERVAL = 3600
EMAIL_TOKEN_CHANNEL = 'resetpassword.email-token'

class EmailTokenPlugin(plugins.SimplePlugin):
    """
    This plugin sends emails with password-reset tokens asynchronously:
    it listens to the bus and spawns a parallel thread for each email to
    be sent.
    """

    def __init__(self, bus, config, logger):
        plugins.SimplePlugin.__init__(self, bus)
        self.config = config
        self._logger = logger

    def start(self):
        self.bus.subscribe(EMAIL_TOKEN_CHANNEL, self.send_email)
        self._log("subscribed to '" + EMAIL_TOKEN_CHANNEL + "'")

    def stop(self):
        self.bus.unsubscribe(EMAIL_TOKEN_CHANNEL, self.send_email)
        self._log('unsubscribed')

    def send_email(self, details):
        self._log('starting _send_email thread')
        emailer = threading.Thread(target=self._send_email, kwargs=details)
        emailer.start()

    def _send_email(self, **details):
        details['url'] = self.config['target_url'] % details
        with open(self.config['email_text']) as email_body:
            email = EmailMessage()
            email['From'] = self.config['email_from']
            email['To'] = details['email']
            email['Subject'] = self.config['email_subject']
            email.set_content(email_body.read() % details)

        if 'sendmail' in self.config:
            subprocess.run([self.config['sendmail'], "-t", "-oi"], input=email.as_bytes())
        elif 'smtp_host' in self.config:
            raise Exception('SMTP not implemented yet')
        else:
            raise Exception('Configuration error: neither sendmail nor SMTP server specified')
        self._log("sent password-reset token for '%(username)s' to <%(email)s>" % details)

    def _log(self, message):
        self._logger(severity=logging.DEBUG, msg='[' + __name__ + '::EmailTokenPlugin] ' + message)


class ResetPassword:
    """
    This class creates and holds password-reset tokens, and runs the actual reset
    """

    def __init__(self, config, backends, logger):
        self.config = config
        self.backends = backends
        self._logger = logger
        # these dicts hold our data
        self.tokens = {}
        self.user_token = {}
        # start plugin to handle emails
        self.emailer = EmailTokenPlugin(cherrypy.engine, config, logger).subscribe()
        # start periodic garbage collection
        self.gc = plugins.BackgroundTask(GC_INTERVAL, self._collect_garbage, bus=cherrypy.engine)
        self.gc.start()

    def _log(self, message):
        self._logger(severity=logging.DEBUG, msg='[' + __name__ + '::ResetPassword] ' + message)

    def _collect_garbage(self):
        """
        delete expired tokens; this will be run by other calls
        (to consider: could be made cronjob for larger deployments)
        """
        kept = 0
        deleted = 0
        # list needs top be copied, deleting keys during iteration not allowed
        tokens = list(self.tokens.keys())
        for token in tokens:
            if self.tokens[token]['expiry'] < datetime.now():
                del self.tokens[token]
                deleted += 1
            else:
                kept += 1
        self._log('token garbage collection: %s expired, %s retained' % (deleted, kept))

    def _make_token(self, username):
        token = token_urlsafe(TOKEN_BYTES)
        hashtoken = sha512(bytes(token, 'utf8')).digest()

        # should be rare, but if there is a collision, just try again...
        if hashtoken in self.tokens:
            return self._make_token(username)

        expiry = datetime.now() + timedelta(minutes=TOKEN_MINUTES)
        self.tokens[hashtoken] = dict(
            username=username,
            expiry=expiry
        )
        self._replace_user_token(username, hashtoken)
        return (token, expiry)

    def _replace_user_token(self, username, hashtoken):
        if username in self.user_token and self.user_token[username] in self.tokens:
            del self.tokens[self.user_token[username]]
            self._log("deleted previous token for '%s'" % (username))
        self.user_token[username] = hashtoken

    def send_token(self, login):
        """
        looks up user by username or email address,
        and sends password-reset token if found
        """
        for b in self.backends.values():
            if hasattr(b, 'get_user_email'):
                try:
                    user = b.get_user_email(login)
                except UserDoesntExist:
                    pass
                else:
                    if user is None:
                        self._log("user/email '%s' not found in '%s'" % (login, b.backend_name) )
                        return
                    self._log("found '%s' in '%s' (search: '%s')" % (user[b.key], b.backend_name, login) )
                    token, expiry = self._make_token(user[b.key])
                    cherrypy.engine.publish(EMAIL_TOKEN_CHANNEL, dict(username=user[b.key], email=user[b.email_user_attr], token=token, expiry=expiry.strftime('%c')))
                    return


    def change_password(self, token, password):
        """
        change password, if token is correct
        """
        hashtoken = sha512(bytes(token, 'utf8')).digest()
        if hashtoken in self.tokens:
            if self.tokens[hashtoken]['expiry'] < datetime.now():
                del self.tokens[hashtoken]
                raise InvalidToken('expired')
            else:
                for b in self.backends.values():
                    if hasattr(b, 'reset_user_password'):
                        self._log("resetting password for '%s' in '%s'" % (self.tokens[hashtoken]['username'], b.backend_name))
                        b.reset_user_password(self.tokens[hashtoken]['username'], password)
                del self.tokens[hashtoken]
                return
        else:
            raise InvalidToken('not found')

