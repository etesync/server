from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission

class Command(BaseCommand):

    def handle(self, *args, **options):
        for permission in Permission.objects.all():
            print(permission.name)
