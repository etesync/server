from django.dispatch import Signal

user_signed_up = Signal(providing_args=['request', 'user'])
