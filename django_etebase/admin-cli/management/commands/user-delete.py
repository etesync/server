from django.core.management.base import BaseCommand
from myauth.models import User

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'username'
                           , type=str
                           , help="Login username of the user to be deleted." )

    def handle(self, *args, **options):
        try:
            User.objects.get(username = options["username"]).delete()
            self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been deleted.'))
        except User.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete user "{options["username"]}": ' + str(exception)))
