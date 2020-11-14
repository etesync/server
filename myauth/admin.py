from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from .models import User
from .forms import AdminUserCreationForm


class UserAdmin(DjangoUserAdmin):
    add_form = AdminUserCreationForm
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("username",),}),)


admin.site.register(User, UserAdmin)
