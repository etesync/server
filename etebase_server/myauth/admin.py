from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .forms import AdminUserCreationForm
from .models import User


class UserAdmin(DjangoUserAdmin):
    add_form = AdminUserCreationForm
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("username",),
            },
        ),
    )


admin.site.register(User, UserAdmin)
