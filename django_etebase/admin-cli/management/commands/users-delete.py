from django.core.management.base import BaseCommand
from myauth.models import User

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'usernames'
                           , default=False
                           , type=str
                           , nargs='*'
                           , default=[]
                           , help="Delete ALL users!" )
        parser.add_argument( '-a'
                           , '--all'
                           , action='store_true'
                           , default=False
                           , help="Delete ALL users!" )

    def handle(self, *args, **options):
        try:
            if options["all"]:
                for user in User.objects.all():
                    user.delete()
                self.stdout.write(self.style.SUCCESS(f'All users have been deleted.'))
            else:
                for username in options["usernames"]:
                    User.objects.get(username=username).delete()
                self.stdout.write(self.style.SUCCESS(f'Users have been deleted.'))
        except User.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete users: ' + str(exception)))
