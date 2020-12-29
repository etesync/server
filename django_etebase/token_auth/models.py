from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from myauth.models import get_typed_user_model

User = get_typed_user_model()


def generate_key():
    return get_random_string(40)


def get_default_expiry():
    return timezone.now() + timezone.timedelta(days=30)


class AuthToken(models.Model):

    key = models.CharField(max_length=40, unique=True, db_index=True, default=generate_key)
    user = models.ForeignKey(User, null=False, blank=False, related_name="auth_token_set", on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    expiry = models.DateTimeField(null=True, blank=True, default=get_default_expiry)

    def __str__(self):
        return "{}: {}".format(self.key, self.user)
