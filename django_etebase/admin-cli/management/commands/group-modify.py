from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.db.utils import IntegrityError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'name'
                           , type=str
                           , help="Group's name." )
        parser.add_argument( '-n'
                           , '--new_name'
                           , '--new-name'
                           , type=str
                           , default=None
                           , help="Group's new name." )
        parser.add_argument( '-m'
                           , '--mode'
                           , type=str
                           , choices=['set', 'add', 'remove']
                           , default='set'
                           , help="Set modification mode. Affects --permissions." )
        parser.add_argument( '--permissions'
                           , type=str
                           , nargs='*'
                           , default=None
                           , help="Group's new permissions." )

    def handle(self, *args, **options):
        try:
            if options["permissions"] != None:
                for index,permission in enumerate(options["permissions"]):
                    options["permissions"][index] = Permission.objects.get(name=permission)

            group = Group.objects.get(name=options["name"])

            if options["new_name"] != None:
                group.name = options["new_name"]
            if options["permissions"] != None:
                if options["mode"] == "set"    : group.permissions.set   ( options["permissions"])
                if options["mode"] == "add"    : group.permissions.add   (*options["permissions"])
                if options["mode"] == "remove" : group.permissions.remove(*options["permissions"])

            group.save()
            self.stdout.write(self.style.SUCCESS(f'Group "{options["name"]}" has been modified.'))

        except (User.DoesNotExist, ValueError) as exception:
            self.stdout.write(self.style.ERROR(f'Unable to modify group "{options["name"]}": ' + str(exception)))
