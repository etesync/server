from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication as DRFTokenAuthentication

from .models import AuthToken, get_default_expiry


AUTO_REFRESH = True
MIN_REFRESH_INTERVAL = 60


class TokenAuthentication(DRFTokenAuthentication):
    keyword = 'Token'
    model = AuthToken

    def authenticate_credentials(self, key):
        msg = _('Invalid token.')
        model = self.get_model()
        try:
            token = model.objects.select_related('user').get(key=key)
        except model.DoesNotExist:
            raise exceptions.AuthenticationFailed(msg)

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed(_('User inactive or deleted.'))

        if token.expiry is not None:
            if token.expiry < timezone.now():
                token.delete()
                raise exceptions.AuthenticationFailed(msg)

            if AUTO_REFRESH:
                self.renew_token(token)

        return (token.user, token)

    def renew_token(self, auth_token):
        current_expiry = auth_token.expiry
        new_expiry = get_default_expiry()
        # Throttle refreshing of token to avoid db writes
        delta = (new_expiry - current_expiry).total_seconds()
        if delta > MIN_REFRESH_INTERVAL:
            auth_token.expiry = new_expiry
            auth_token.save(update_fields=('expiry',))
