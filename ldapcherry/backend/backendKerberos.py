# -*- coding: utf-8 -*-
# vim:set expandtab tabstop=4 shiftwidth=4:
#
# Backend to create Kerberos principals
#
# Copyright (c) 2020 Colin Tück

import sys
import re
import logging
from socket import getfqdn

import cherrypy
import kadmin

import ldapcherry.backend
from ldapcherry.exceptions import UserDoesntExist, \
    GroupDoesntExist, MissingParameter, \
    UserAlreadyExists, PermissionDenied, \
    PPolicyError

if sys.version < '3':
    from sets import Set as set

SESSION_PRINCIPAL = '_krb_principal'
SESSION_PASSWORD = '_krb_password'

class Backend(ldapcherry.backend.Backend):

    def __init__(self, config, logger, name, attrslist, key):
        """ Initialize the backend

        :param config: the configuration of the backend
        :type config: dict {'config key': 'value'}
        :param logger: the cherrypy error logger object
        :type logger: python logger
        :param name: id of the backend
        :type name: string
        :param attrslist: list of the backend attributes
        :type attrslist: list of strings
        :param key: the key attribute
        :type key: string
        """
        self._logger = logger
        self.backend_name = name
        self.key = key
        self.config = config
        if 'principal' not in self.config:
            self.config['principal'] = 'ldapcherry/' + getfqdn()

    def kadm(self, as_admin=False):
        """
        return a context manager to connect with admin or user kadmin connection, depending on role
        """
        class KadmContext():
            def __init__(self, backend, as_admin=False):
                self.backend = backend
                self.as_admin = as_admin

            def __enter__(self):
                if cherrypy.session.get('isadmin', False) or self.as_admin:
                    self.kadm = kadmin.init_with_keytab(self.backend.config['principal'], self.backend.config['keytab'])
                elif cherrypy.session.get(SESSION_PRINCIPAL, None) and cherrypy.session.get(SESSION_PASSWORD, None):
                    self.kadm = kadmin.init_with_password(cherrypy.session.get(SESSION_PRINCIPAL), cherrypy.session.get(SESSION_PASSWORD))
                else:
                    raise PermissionDenied('(corrupted session)', self.backend.backend_name)
                return self.kadm

            def __exit__(self, exc_type, exc_value, traceback):
                del self.kadm
                return None

        return KadmContext(self, as_admin)

    def _user2princ(self, username):
        return('{}@{}'.format(username, self.config['realm']))

    def _log(self, message):
        self._logger(severity=logging.DEBUG, msg='[' + __name__ + '::Backend] ' + message)

    def _add_princ(self, principal, password = None):
        with self.kadm() as kadm:
            try:
                self.kadm.addprinc(principal, password)
            except kadmin.DuplicateError:
                raise UserAlreadyExists(principal, self.backend_name)

    def _get_princ(self, principal, as_admin=False):
        with self.kadm(as_admin) as kadm:
            obj = kadm.getprinc(principal)
            if obj:
                return obj
            else:
                raise UserDoesntExist(principal, self.backend_name)

    def _change_password(self, principal, password, reset_by_token=False):
        try:
            self._get_princ(principal, as_admin=reset_by_token).change_password(password)
            if not reset_by_token:
                cherrypy.session[SESSION_PASSWORD] = password
        except kadmin.PasswordClassError:
            raise PPolicyError(reason='password does not contain enough character classes')
        except kadmin.PasswordTooShortError:
            raise PPolicyError(reason='password is too short')

    def _del_princ(self, principal):
        with self.kadm() as kadm:
            try:
                kadm.delprinc(principal)
            except kadmin.UnknownPrincipalError:
                raise UserDoesntExist(principal, self.backend_name)

    def auth(self, username, password):
        """ Check authentication against the backend

        :param username: 'key' attribute of the user
        :type username: string
        :param password: password of the user
        :type password: string
        :rtype: boolean (True is authentication success, False otherwise)
        """
        try:
            self._log("trying auth with username '%s' = principal '%s'" % (username, self._user2princ(username)))
            kadm = kadmin.init_with_password(self._user2princ(username), password)
        except kadmin.KRB5KDCClientNotFoundError:
            """ user unknown """
            return False
        except kadmin.KRB5KDCPreauthFailedError:
            """ wrong password, with pre-auth """
            return False
        except kadmin.PasswordError:
            """ wrong password, without pre-auth """
            return False
        else:
            cherrypy.session[SESSION_PRINCIPAL] = self._user2princ(username)
            cherrypy.session[SESSION_PASSWORD] = password
            return True

    def reset_user_password(self, username, password):
        """ reset password (called by email token app) """
        self._log("resetting password of user '%s' = principal '%s' (email token-based)" % (username, self._user2princ(username)))
        self._change_password(self._user2princ(username), password, reset_by_token=True)

    def add_user(self, attrs):
        """ Add a user to the backend

        :param attrs: attributes of the user
        :type attrs: dict ({<attr>: <value>})

        .. warning:: raise UserAlreadyExists if user already exists
        """
        if self.key not in attrs:
            raise MissingUserKey()
        new_principal = self._user2princ(attrs[self.key])

        if 'password' in attrs and attrs['password']:
            self._log("adding new principal '%s' with password" % (new_principal))
            self._add_princ(new_principal, attrs['password'])
        else:
            self._log("adding new principal '%s' without password" % (new_principal))
            self._add_princ(new_principal)


    def del_user(self, username):
        """ Delete a user from the backend

        :param username: 'key' attribute of the user
        :type username: string

        """
        self._log("deleting user '%s' = principal '%s'" % (username, self._user2princ(username)))
        self._del_princ(self._user2princ(username))


    def set_attrs(self, username, attrs):
        """ set a list of attributes for a given user

        :param username: 'key' attribute of the user
        :type username: string
        :param attrs: attributes of the user
        :type attrs: dict ({<attr>: <value>})
        """
        if 'password' in attrs and attrs['password']:
            self._log("setting password of user '%s' = principal '%s'" % (username, self._user2princ(username)))
            self._change_password(self._user2princ(username), attrs['password'])
        else:
            pass

    def add_to_groups(self, username, groups):
        """ Add a user to a list of groups

        :param username: 'key' attribute of the user
        :type username: string
        :param groups: list of groups
        :type groups: list of strings
        """
        if len(groups) > 0:
            raise GroupDoesntExist(groups[0], self.backend_name)
        else:
            pass

    def del_from_groups(self, username, groups):
        """ Delete a user from a list of groups

        :param username: 'key' attribute of the user
        :type username: string
        :param groups: list of groups
        :type groups: list of strings

        .. warning:: raise GroupDoesntExist if group doesn't exist
        """
        if len(groups) > 0:
            raise GroupDoesntExist(groups[0], self.backend_name)
        else:
            pass

    def search(self, searchstring):
        """ Search backend for users

        :param searchstring: the search string
        :type searchstring: string
        :rtype: dict of dict ( {<user attr key>: {<attr>: <value>}} )
        """
        return {}

    def get_user(self, username):
        """ Get a user's attributes

        :param username: 'key' attribute of the user
        :type username: string
        :rtype: dict ( {<attr>: <value>} )

        .. warning:: raise UserDoesntExist if user doesn't exist
        """
        self._log("getting profile of user '%s' = principal '%s'" % (username, self._user2princ(username)))
        principal = self._get_princ(self._user2princ(username))
        ret = dict(
                principal=principal.principal,
                last_failure=principal.last_failure,
                last_success=principal.last_success,
                last_pwd_change=principal.last_pwd_change,
                mod_date=principal.mod_date,
                mod_name=principal.mod_name,
            )
        return ret

    def get_groups(self, username):
        """ Get a user's groups

        :param username: 'key' attribute of the user
        :type username: string
        :rtype: list of groups
        """
        return []

