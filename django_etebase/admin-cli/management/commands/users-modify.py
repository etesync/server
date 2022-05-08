from django.core.management.base import BaseCommand
from ._utils import argbool
from myauth.models import User
from django.db.utils import IntegrityError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'username'
                           , type=str
                           , help="User's login username." )
        parser.add_argument( '-u'
                           , '--new_username'
                           , '--new-username'
                           , type=str
                           , default=None
                           , help="User's new login username." )
        parser.add_argument( '-f'
                           , '--first_name'
                           , '--first-name'
                           , '--first'
                           , type=str
                           , default=None
                           , help="User's new first name." )
        parser.add_argument( '-l'
                           , '--last_name'
                           , '--last-name'
                           , '--last'
                           , type=str
                           , default=None
                           , help="User's new last name." )
        parser.add_argument( '-e'
                           , '--email'
                           , type=str
                           , default=None
                           , help="User's new email address." )
        parser.add_argument( '-a'
                           , '--is_active'
                           , '--is-active'
                           , '--active'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=None
                           , help="Enable/Disable login." )
        parser.add_argument( '-s'
                           , '--is_staff'
                           , '--is-staff'
                           , '--staff'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=None
                           , help="Mark/Unmark user as staff." )
        parser.add_argument( '-S'
                           , '--is_superuser'
                           , '--is-superuser'
                           , '--superuser'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=None
                           , help="Mark/Unmark user as superuser." )

    def handle(self, *args, **options):
        try:
            user = User.objects.get(username = options["username"])
            if options["new_username"] != None: user.username     = options["new_username"]
            if options["email"       ] != None: user.email        = options["email"       ]
            if options["first_name"  ] != None: user.first_name   = options["first_name"  ]
            if options["last_name"   ] != None: user.last_name    = options["last_name"   ]
            if options["is_active"   ] != None: user.is_active    = options["is_active"   ]
            if options["is_staff"    ] != None: user.is_staff     = options["is_staff"    ]
            if options["is_superuser"] != None: user.is_superuser = options["is_superuser"]
            user.save()
        except (User.DoesNotExist, ValueError) as exception:
            self.stdout.write(self.style.ERROR(f'Unable to modify user "{options["username"]}": ' + str(exception)))
            exit(1)

        self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been modified.'))
        exit(0)
