from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

class Command(BaseCommand):

    def handle(self, *args, **options):
        for group in Group.objects.all():
            print(group.name)
