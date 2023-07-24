import logging

from django.utils import timezone
from django.conf import settings
from django.core.exceptions import PermissionDenied as DjangoPermissionDenied
from etebase_server.django.utils import CallbackContext
from etebase_server.myauth.models import get_typed_user_model, UserType
from etebase_server.fastapi.dependencies import get_authenticated_user
from etebase_server.fastapi.exceptions import PermissionDenied as FastAPIPermissionDenied
from fastapi import Depends

import ldap

User = get_typed_user_model()


def ldap_setting(name, default):
    """Wrapper around django.conf.settings"""
    return getattr(settings, f"LDAP_{name}", default)


class LDAPConnection:
    __instance__ = None
    __user_cache = {}  # Username -> Valid until

    @staticmethod
    def get_instance():
        """To get a Singleton"""
        if not LDAPConnection.__instance__:
            return LDAPConnection()
        else:
            return LDAPConnection.__instance__

    def __init__(self):
        # Cache some settings
        self.__LDAP_FILTER = ldap_setting("FILTER", "")
        self.__LDAP_SEARCH_BASE = ldap_setting("SEARCH_BASE", "")

        # The time a cache entry is valid (in hours)
        try:
            self.__LDAP_CACHE_TTL = int(ldap_setting("CACHE_TTL", ""))
        except ValueError:
            logging.error("Invalid value for cache_ttl. Defaulting to 1 hour")
            self.__LDAP_CACHE_TTL = 1

        password = ldap_setting("BIND_PW", "")
        if not password:
            pw_file = ldap_setting("BIND_PW_FILE", "")
            if pw_file:
                with open(pw_file, "r") as f:
                    password = f.read().replace("\n", "")

        self.__ldap_connection = ldap.initialize(ldap_setting("SERVER", ""))
        try:
            self.__ldap_connection.simple_bind_s(ldap_setting("BIND_DN", ""), password)
        except ldap.LDAPError as err:
            logging.error(f"LDAP Error occurring during bind: {err.desc}")

    def __is_cache_valid(self, username):
        """Returns True if the cache entry is still valid. Returns False otherwise."""
        if username in self.__user_cache:
            if timezone.now() <= self.__user_cache[username]:
                # Cache entry is still valid
                return True
        return False

    def __remove_cache(self, username):
        del self.__user_cache[username]

    def has_user(self, username):
        """
        Since we don't care about the password and so authentication
        another way, all we care about is whether the user exists.
        """
        if self.__is_cache_valid(username):
            return True
        if username in self.__user_cache:
            self.__remove_cache(username)

        filterstr = self.__LDAP_FILTER.replace("%s", username)
        try:
            result = self.__ldap_connection.search_s(self.__LDAP_SEARCH_BASE, ldap.SCOPE_SUBTREE, filterstr=filterstr)
        except ldap.NO_RESULTS_RETURNED:
            # We handle the specific error first and the the generic error, as
            # we may expect ldap.NO_RESULTS_RETURNED, but not any other error
            return False
        except ldap.LDAPError as err:
            logging.error(f"Error occurred while performing an LDAP query: {err.desc}")
            return False

        if len(result) == 1:
            self.__user_cache[username] = timezone.now() + timezone.timedelta(hours=self.__LDAP_CACHE_TTL)
            return True
        return False


def is_user_in_ldap(user: UserType = Depends(get_authenticated_user)):
    if not LDAPConnection.get_instance().has_user(user.username):
        raise FastAPIPermissionDenied(detail="User not in LDAP directory.")


def create_user(context: CallbackContext, *args, **kwargs):
    """
    A create_user function which first checks if the user already exists in the
    configured LDAP directory.
    """
    if not LDAPConnection.get_instance().has_user(kwargs["username"]):
        raise DjangoPermissionDenied("User not in the LDAP directory.")
    return User.objects.create_user(*args, **kwargs)
