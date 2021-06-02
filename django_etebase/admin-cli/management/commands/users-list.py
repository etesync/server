from django.core.management.base import BaseCommand
from myauth.models import User

class Command(BaseCommand):

    def handle(self, *args, **options):
        for user in User.objects.all():
            print(user.username)
