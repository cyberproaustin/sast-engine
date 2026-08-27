"""The permission classes the views declare, and what each of them is ABOUT.

The key a permission consults is the whole left half of the relation, and it is never in
the view that declares the permission -- doccano's six role classes all inherit one
`get_workspace_id` equivalent from one base, three packages from any view that names it.
"""
from rest_framework.permissions import SAFE_METHODS, BasePermission


class RolePermission(BasePermission):
    """The base every role below inherits, and the only place the key is read.

    A lookup that stopped at the subclass would find no key on any of the four roles, so
    the base chain has to be followed to see what the check is scoped to.
    """

    role_name = ""

    @classmethod
    def get_workspace_id(cls, request, view):
        return view.kwargs.get("workspace_id")

    def has_permission(self, request, view):
        workspace_id = self.get_workspace_id(request, view)
        return Membership.objects.filter(
            workspace=workspace_id, user=request.user, role=self.role_name
        ).exists()


class IsWorkspaceAdmin(RolePermission):
    role_name = "admin"


class IsWorkspaceEditor(RolePermission):
    role_name = "editor"


class IsWorkspaceViewer(RolePermission):
    role_name = "viewer"

    def has_permission(self, request, view):
        return request.method in SAFE_METHODS and super().has_permission(request, view)


# Composed under a second name, which is how DRF applications spell "any of these".
# The views that use it never mention the three classes it stands for, so the alias has
# to be resolved before the scope can be read off it.
IsWorkspaceMember = IsWorkspaceAdmin | IsWorkspaceEditor | IsWorkspaceViewer


class IsOwner(BasePermission):
    """The framework's own hook for relating the SELECTED row to the requester.

    A view that declares one of these has answered the question in the place the framework
    provides for answering it, whichever URL keys its other permissions name.
    """

    def has_object_permission(self, request, view, obj):
        return obj.owner_id == request.user.id


class IsSignedIn(BasePermission):
    """A check about the caller and about no record at all.

    This is the shape 52 of wger's declared views have. It says something true and says
    nothing about which row is being touched, so the relation this analysis states does
    not apply -- and a rule that reported it would report the ordinary spelling of every
    authenticated API in existence.
    """

    def has_permission(self, request, view):
        return request.user.is_authenticated
