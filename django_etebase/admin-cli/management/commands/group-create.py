from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.db.utils import IntegrityError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'name'
                           , type=str
                           , help="New group's name." )
        parser.add_argument( '--permissions'
                           , type=str
                           , nargs='*'
                           , default=[]
                           , help="New group's permissions." )

    def handle(self, *args, **options):
        try:
            for index,permission in enumerate(options["permissions"]):
                options["permissions"][index] = Permission.objects.get(name=permission)

            group = Group.objects.create(name=options["name"])
            group.permissions.set(options["permissions"])
            group.save()
        except (IntegrityError,Permission.DoesNotExist) as exception:
            self.stdout.write(self.style.ERROR(f'Unable to create group "{options["name"]}": ' + str(exception)))
            exit(1)

        self.stdout.write(self.style.SUCCESS(f'Group "{options["name"]}" has been created.'))
        exit(0)
