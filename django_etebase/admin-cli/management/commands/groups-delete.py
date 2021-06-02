from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( '-y'
                           , '--yes'
                           , action='store_true'
                           , default=False
                           , help="Allow deletion of all groups!" )

    def handle(self, *args, **options):
        if options["yes"] != True:
            print('Do you really want to delete all groups? [y/N]: ', end='')
            if input() not in ('y', 'Y', 'yes', 'YES', 'Yes'):
                self.stdout.write(self.style.SUCCESS(f'No groups have been deleted.'))
                exit(0)

        try:
            for group in Group.objects.all():
                group.delete()
            self.stdout.write(self.style.SUCCESS(f'All groups have been deleted.'))
            exit(0)
        except Group.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete all groups: ' + str(exception)))
            exit(1)
