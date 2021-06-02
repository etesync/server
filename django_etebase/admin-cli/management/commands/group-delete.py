from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'name'
                           , type=str
                           , help="Name of the group to be deleted." )

    def handle(self, *args, **options):
        try:
            Group.objects.get(name = options["name"]).delete()
            self.stdout.write(self.style.SUCCESS(f'Grop "{options["name"]}" has been deleted.'))
        except Group.DoesNotExist as exception:
            self.stdout.write(self.style.ERROR(f'Unable to delete group "{options["name"]}": ' + str(exception)))
