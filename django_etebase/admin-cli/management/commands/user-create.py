from django.core.management.base import BaseCommand
from django_etebase.users.management.commands._utils import argbool, argdate
from myauth.models import User
from django.contrib.auth.models import Group, Permission
from django.db.utils import IntegrityError

class Command(BaseCommand):

    def add_arguments(self, parser):
        parser.add_argument( 'username'
                           , type=str
                           , help="New user's login username." )
        parser.add_argument( '-p'
                           , '--password'
                           , type=str
                           , help="New user's plain text login password." )
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
                           , default=False
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
        parser.add_argument( '-g'
                           , '--groups'
                           , type=str
                           , nargs='*'
                           , default=[]
                           , help="New user's groups." )
        parser.add_argument( '--user_permissions'
                           , '--user-permissions'
                           , '--permissions'
                           , type=str
                           , nargs='*'
                           , default=[]
                           , help="New user's user permissions." )
        parser.add_argument( '-j'
                           , '--date_joined'
                           , '--date-joined'
                           , type=str
                           , default=None
                           , help="New user's date joined, formated as '%Y-%m-%d %H:%M:%S.%f'." )
        parser.add_argument( '--last_login'
                           , '--last-login'
                           , type=str
                           , default=None
                           , help="New user's last login date, formated as '%Y-%m-%d %H:%M:%S.%f'." )

    def handle(self, *args, **options):
        try:
            for index,group in enumerate(options["groups"]):
                options["groups"][index] = Group.objects.get(name=group)
            for index,permission in enumerate(options["user_permissions"]):
                options["user_permissions"][index] = Permission.objects.get(name=permission)
            options["date_joined"] = argdate(options["date_joined"])
            options["last_login" ] = argdate(options["last_login" ])

            user = User.objects.create_user( username         = options["username"         ]
                                           , password         = options["password"         ]
                                           , email            = options["email"            ]
                                           , first_name       = options["first_name"       ]
                                           , last_name        = options["last_name"        ]
                                           , is_superuser     = options["is_superuser"     ]
                                           , is_staff         = options["is_staff"         ]
                                           , is_active        = options["is_active"        ]
                                           , last_login       = options["last_login"       ] )
            user.groups.set(options["groups"])
            user.user_permissions.set(options["user_permissions"])
            if options["date_joined"] != None:
                user.date_joined = options["date_joined"]
            user.save()
        except (IntegrityError,Group.DoesNotExist,Permission.DoesNotExist) as exception:
            self.stdout.write(self.style.ERROR(f'Unable to create user "{options["username"]}": ' + str(exception)))
            exit(1)

        self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been created.'))
        exit(0)
