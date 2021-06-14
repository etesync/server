from django.core.management.base import BaseCommand
from myauth.models import User
from django.db.models.deletion import ProtectedError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'username'
                           , type=str
                           , help="Login username of the user to be deleted." )
        parser.add_argument( '--delete-user-data'
                           , action='store_true'
                           , default=False
                           , help="Delete all user's collections!" )

    def handle(self, *args, **options):
        try:
            user = User.objects.get(username = options["username"])
            if options["delete_user_data"]:
                collections = user.collection_set.all()
                for collection in collections:
                    collection.delete()
            user.delete()
        except User.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete user "{options["username"]}": ' + str(exception)))
            exit(1)
        except ProtectedError as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete user "{options["username"]}": ' + str(exception)))
            self.stdout.write(self.style.NOTICE('Use --delete-user-data to overcome this protection.'))
            exit(2)

        self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been deleted.'))
        exit(0)
