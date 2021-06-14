from django.core.management.base import BaseCommand
from ._utils import argbool
from myauth.models import User
from django.db.utils import IntegrityError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'username'
                           , type=str
                           , help="New user's login username." )
        parser.add_argument( '-f'
                           , '--first_name'
                           , '--first'
                           , type=str
                           , default=''
                           , help="New user's first name." )
        parser.add_argument( '-l'
                           , '--last_name'
                           , '--last'
                           , type=str
                           , default=''
                           , help="New user's last name." )
        parser.add_argument( '-e'
                           , '--email'
                           , type=str
                           , default=''
                           , help="New user's email address." )
        parser.add_argument( '-a'
                           , '--is_active'
                           , '--active'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=True
                           , help="Enable login. [YES]" )
        parser.add_argument( '-s'
                           , '--is_staff'
                           , '--staff'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=False
                           , help="Mark user as staff. [NO]" )
        parser.add_argument( '-S'
                           , '--is_superuser'
                           , '--superuser'
                           , nargs='?'
                           , type=argbool
                           , const=True
                           , default=False
                           , help="Mark user as superuser. [NO]" )

    def handle(self, *args, **options):
        try:
            User.objects.create_user( username         = options["username"    ]
                                    , email            = options["email"       ]
                                    , first_name       = options["first_name"  ]
                                    , last_name        = options["last_name"   ]
                                    , is_active        = options["is_active"   ]
                                    , is_staff         = options["is_staff"    ]
                                    , is_superuser     = options["is_superuser"] )
        except IntegrityError as exception:
            self.stdout.write(self.style.ERROR(f'Unable to create user "{options["username"]}": ' + str(exception)))
            exit(1)

        self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been created.'))
        exit(0)
