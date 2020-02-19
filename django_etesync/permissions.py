# Copyright © 2017 Tom Hacohen
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, version 3.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from rest_framework import permissions
from journal.models import Journal, JournalMember


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    """

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True

        return obj.owner == request.user


class IsJournalOwner(permissions.BasePermission):
    """
    Custom permission to only allow owners of a journal to view it
    """

    def has_permission(self, request, view):
        journal_uid = view.kwargs['journal_uid']
        try:
            journal = view.get_journal_queryset().get(uid=journal_uid)
            return journal.owner == request.user
        except Journal.DoesNotExist:
            # If the journal does not exist, we want to 404 later, not permission denied.
            return True


class IsMemberReadOnly(permissions.BasePermission):
    """
    Custom permission to make a journal read only if a read only member
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        journal_uid = view.kwargs['journal_uid']
        try:
            journal = view.get_journal_queryset().get(uid=journal_uid)
            member = journal.members.get(user=request.user)
            return not member.readOnly
        except Journal.DoesNotExist:
            # If the journal does not exist, we want to 404 later, not permission denied.
            return True
        except JournalMember.DoesNotExist:
            # Not being a member means we are the owner.
            return True
