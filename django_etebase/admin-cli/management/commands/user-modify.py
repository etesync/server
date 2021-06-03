from django.core.management.base import BaseCommand
from ._utils import argbool, argdate
from myauth.models import User
from django.contrib.auth.models import Group, Permission
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
        parser.add_argument( '-p'
                           , '--password'
                           , type=str
                           , help="User's new plain text login password." )
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
        parser.add_argument( '-m'
                           , '--mode'
                           , type=str
                           , choices=['set', 'add', 'remove']
                           , default='set'
                           , help="Set modification mode. Affects --groups and --user_permissions." )
        parser.add_argument( '-g'
                           , '--groups'
                           , type=str
                           , nargs='*'
                           , default=None
                           , help="User's new groups." )
        parser.add_argument( '--user_permissions'
                           , '--user-permissions'
                           , '--permissions'
                           , type=str
                           , nargs='*'
                           , default=None
                           , help="User's new user permissions." )
        parser.add_argument( '-j'
                           , '--date_joined'
                           , '--date-joined'
                           , type=str
                           , default=None
                           , help="User's new date joined, formated as '%Y-%m-%d %H:%M:%S.%f'." )
        parser.add_argument( '--last_login'
                           , '--last-login'
                           , type=str
                           , default=None
                           , help="User's new last login date, formated as '%Y-%m-%d %H:%M:%S.%f'." )

    def handle(self, *args, **options):
        try:
            if options["groups"] != None:
                for index,group in enumerate(options["groups"]):
                    options["groups"][index] = Group.objects.get(name=group)
            if options["user_permissions"] != None:
                for index,permission in enumerate(options["user_permissions"]):
                    options["user_permissions"][index] = Permission.objects.get(name=permission)
            options["date_joined"] = argdate(options["date_joined"])
            options["last_login" ] = argdate(options["last_login" ])

            user = User.objects.get(username = options["username"])

            if options["new_username"] != None: user.username     = options["new_username"]
            if options["password"    ] != None: user.password     = options["password"    ]
            if options["email"       ] != None: user.email        = options["email"       ]
            if options["first_name"  ] != None: user.first_name   = options["first_name"  ]
            if options["last_name"   ] != None: user.last_name    = options["last_name"   ]
            if options["is_active"   ] != None: user.is_active    = options["is_active"   ]
            if options["is_staff"    ] != None: user.is_staff     = options["is_staff"    ]
            if options["is_superuser"] != None: user.is_superuser = options["is_superuser"]
            if options["date_joined" ] != None: user.date_joined  = options["date_joined" ]
            if options["last_login"  ] != None: user.last_login   = options["last_login"  ]

            if options["groups"] != None:
                if options["mode"] == "set"    : user.groups.set   ( options["groups"])
                if options["mode"] == "add"    : user.groups.add   (*options["groups"])
                if options["mode"] == "remove" : user.groups.remove(*options["groups"])
            if options["user_permissions"] != None:
                if options["mode"] == "set"    : user.user_permissions.set   ( options["user_permissions"])
                if options["mode"] == "add"    : user.user_permissions.add   (*options["user_permissions"])
                if options["mode"] == "remove" : user.user_permissions.remove(*options["user_permissions"])

            user.save()
            self.stdout.write(self.style.SUCCESS(f'User "{options["username"]}" has been modified.'))

        except (User.DoesNotExist, ValueError) as exception:
            self.stdout.write(self.style.ERROR(f'Unable to modify user "{options["username"]}": ' + str(exception)))
