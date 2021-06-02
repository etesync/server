from django.core.management.base import BaseCommand
from myauth.models import User

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( '-y'
                           , '--yes'
                           , action='store_true'
                           , default=False
                           , help="Allow deletion of all users!" )

    def handle(self, *args, **options):
        if options["yes"] != True:
            print('Do you really want to delete all users? [y/N]: ', end='')
            if input()[0] not in ('y', 'Y', 'yes', 'YES', 'Yes'):
                self.stdout.write(self.style.SUCCESS(f'No users have been deleted.'))
                exit(0)

        try:
            for user in User.objects.all():
                user.delete()
            self.stdout.write(self.style.SUCCESS(f'All users have been deleted.'))
        except User.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete all users: ' + str(exception)))
