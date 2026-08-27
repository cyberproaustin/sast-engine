"""Views with no request handling in them, which is the whole difficulty.

Every class here is registered, answers requests, and reaches a store. None of them
contains a gate call, an operation call, or a control-flow graph to relate the two in:
`permission_classes` decides who may proceed and `queryset` plus `lookup_url_kwarg`
decides which row is fetched, and the framework does both. An analysis that relates one
call to another sees an empty class body and reports nothing.

The positives and the negatives differ by one line each, and the line is always the same
question: is the row the framework fetches inside the scope the permission checked?
"""
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import (
    Attachment,
    Comment,
    Document,
    Folder,
    Label,
    Note,
    Revision,
    Share,
    Tag,
    Task,
    Workspace,
)
from .permissions import (
    IsOwner,
    IsSignedIn,
    IsWorkspaceAdmin,
    IsWorkspaceMember,
    IsWorkspaceViewer,
)


class DocumentList(generics.ListCreateAPIView):
    """NEGATIVE. The relation written the way a correct view writes it.

    The permission is about `workspace_id` and the query is narrowed by `workspace_id`,
    so the framework cannot reach a row outside what was checked.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceMember]

    def get_queryset(self):
        return Document.objects.filter(workspace=self.kwargs["workspace_id"])

    def perform_create(self, serializer):
        serializer.save(workspace_id=self.kwargs["workspace_id"])


class DocumentDetail(generics.RetrieveUpdateDestroyAPIView):
    """POSITIVE. The shape, at its plainest.

    `IsWorkspaceMember` proves the caller belongs to the workspace in the URL. The
    framework then fetches whatever document `document_id` names, out of every document
    in the installation, and serves it to GET, PUT, PATCH and DELETE alike. Nothing
    relates the document to the workspace, and a member of one workspace reads and
    deletes another's by changing one number in the path.
    """

    queryset = Document.objects.all()
    lookup_url_kwarg = "document_id"
    permission_classes = [IsAuthenticated & IsWorkspaceMember]


class FolderDetail(generics.RetrieveUpdateDestroyAPIView):
    """NEGATIVE. The same shape with the relation restored by one override.

    The declared queryset is still global; `get_queryset` narrows it to the workspace the
    permission was about, and the lookup then chooses among rows that are already inside
    the authorized scope.
    """

    queryset = Folder.objects.all()
    lookup_url_kwarg = "folder_id"
    permission_classes = [IsAuthenticated & IsWorkspaceAdmin]

    def get_queryset(self):
        return Folder.objects.filter(workspace=self.kwargs["workspace_id"])


class WorkspaceDetail(generics.RetrieveUpdateAPIView):
    """NEGATIVE. The record the permission is about IS the record it fetches.

    A global queryset and no narrowing at all, and correct: the key the framework selects
    by is the key the check was scoped to.
    """

    queryset = Folder.objects.all()
    lookup_url_kwarg = "workspace_id"
    permission_classes = [IsAuthenticated & IsWorkspaceAdmin]


class NoteDetail(generics.RetrieveUpdateDestroyAPIView):
    """NEGATIVE. The relation stated in the framework's own hook.

    `note_id` is not `workspace_id` and nothing narrows the queryset, which is the
    positive's shape exactly. It is silent because `IsOwner` declares
    `has_object_permission`, and DRF hands that the row it selected -- the relation is
    between the record and the requester rather than between two URL keys, and it is made
    in the place provided for making it.
    """

    queryset = Note.objects.all()
    lookup_url_kwarg = "note_id"
    permission_classes = [IsAuthenticated & IsWorkspaceMember & IsOwner]


class TaskViewSet(generics.ListCreateAPIView):
    """NEGATIVE. Authorization that is about the caller and about no record.

    This is what 52 of wger's declared views look like: a role check with no key in it,
    and a query narrowed by the requester instead of by anything in the URL. There is no
    authorized scope to compare a selection against, so this analysis has no claim to
    make -- the question of whether the view is authorized at all belongs to the ownership
    policy, which asks the other one.
    """

    queryset = Task.objects.all()
    permission_classes = [IsSignedIn]

    def get_queryset(self):
        return Task.objects.filter(assignee=self.request.user)


class RevisionListBase(generics.ListAPIView):
    """POSITIVE, declared here and registered three classes down.

    The permission is about the workspace; the query is narrowed to whatever document the
    caller named, and no check was ever about that document. A viewer of one workspace
    reads every revision of every document in the installation, one document at a time.

    The finding is reported once, at this line, however many subclasses inherit it.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceViewer]

    def get_queryset(self):
        return Revision.objects.filter(document=self.kwargs["document_id"])


class TextRevisionList(RevisionListBase):
    serializer_class = None


class BinaryRevisionList(RevisionListBase):
    serializer_class = None


class CommentDetailBase(generics.RetrieveDestroyAPIView):
    """The declarations split across the chain, which is how applications write them.

    The base names the lookup key and each subclass names only its model, so a reader of
    either file alone sees half the relation. Silent, because the base also narrows the
    query to the workspace the permission checked.
    """

    lookup_url_kwarg = "comment_id"
    permission_classes = [IsAuthenticated & IsWorkspaceMember]

    def get_queryset(self):
        return Comment.objects.filter(workspace=self.kwargs["workspace_id"])


class ThreadCommentDetail(CommentDetailBase):
    """NEGATIVE. Inherits the lookup key AND the narrowing that relates it."""

    queryset = Comment.objects.all()


# A declaratively authorized view is not always empty. It routinely carries one method the
# framework has no opinion about -- a bulk delete taking a list of primary keys out of the
# request body -- and that method runs under an authorization it never mentions, because
# the class declared it. Everything below is that half.


class TagList(generics.ListCreateAPIView):
    """POSITIVE. The class states the scope and the bulk delete does not use it.

    `get_queryset` narrows the LIST to the workspace the permission checked, which makes
    the delete beside it read as though it were narrowed too. It is not: the framework
    never calls `get_queryset` for a method the application wrote itself, so the primary
    keys go straight from the request body to the store, and an admin of one workspace
    deletes another's tags.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceAdmin]

    def get_queryset(self):
        return Tag.objects.filter(workspace=self.kwargs["workspace_id"])

    def delete(self, request, *args, **kwargs):
        Tag.objects.filter(pk__in=request.data["ids"]).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class LabelList(generics.ListCreateAPIView):
    """NEGATIVE. The same bulk delete with the authorized key in the selection.

    One extra term, and the rows the caller can reach are inside what was checked. This is
    the shape the positive above is one word away from.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceAdmin]

    def get_queryset(self):
        return Label.objects.filter(workspace=self.kwargs["workspace_id"])

    def delete(self, request, *args, **kwargs):
        Label.objects.filter(
            workspace=self.kwargs["workspace_id"], pk__in=request.data["ids"]
        ).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AttachmentList(generics.ListCreateAPIView):
    """NEGATIVE. Narrowed by the REQUESTER rather than by the authorized key.

    A row the caller does not own is unreachable however many keys the call also carries,
    and that is a relation to the caller directly rather than to the key the permission
    named. The ownership policy asks that question; this one has nothing left to say.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceMember]

    def get_queryset(self):
        return Attachment.objects.filter(workspace=self.kwargs["workspace_id"])

    def delete(self, request, *args, **kwargs):
        Attachment.objects.filter(owner=request.user, pk__in=request.data["ids"]).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ShareList(generics.ListCreateAPIView):
    """NEGATIVE. Narrowed through the view's own accessor, which says so nowhere.

    `self.workspace.shares` is already inside the authorized workspace and the handler
    body does not contain a single word saying it: `workspace` is a property elsewhere in
    the class that fetches the row the URL names. A reader who does not follow the
    attribute sees the positive above.
    """

    permission_classes = [IsAuthenticated & IsWorkspaceAdmin]

    @property
    def workspace(self):
        return get_object_or_404(Workspace, pk=self.kwargs["workspace_id"])

    def get_queryset(self):
        return Share.objects.filter(workspace=self.workspace)

    def delete(self, request, *args, **kwargs):
        self.workspace.shares.filter(pk__in=request.data["ids"]).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
