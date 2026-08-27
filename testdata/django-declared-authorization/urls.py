"""The registration, which is the only evidence any of these classes is reachable.

A class that merely looks like a view -- an abstract base, a mixin -- answers no request,
and the analysis reads nothing that a URLconf did not name.
"""
from django.urls import path

from .views import (
    AttachmentList,
    BinaryRevisionList,
    DocumentDetail,
    DocumentList,
    FolderDetail,
    LabelList,
    NoteDetail,
    ShareList,
    TagList,
    TaskViewSet,
    TextRevisionList,
    ThreadCommentDetail,
    WorkspaceDetail,
)

urlpatterns = [
    path("workspaces/<int:workspace_id>", WorkspaceDetail.as_view(), name="workspace"),
    path("workspaces/<int:workspace_id>/documents", DocumentList.as_view(), name="documents"),
    path(
        "workspaces/<int:workspace_id>/documents/<int:document_id>",
        DocumentDetail.as_view(),
        name="document",
    ),
    path(
        "workspaces/<int:workspace_id>/documents/<int:document_id>/revisions/text",
        TextRevisionList.as_view(),
        name="text_revisions",
    ),
    path(
        "workspaces/<int:workspace_id>/documents/<int:document_id>/revisions/binary",
        BinaryRevisionList.as_view(),
        name="binary_revisions",
    ),
    path(
        "workspaces/<int:workspace_id>/folders/<int:folder_id>",
        FolderDetail.as_view(),
        name="folder",
    ),
    path("workspaces/<int:workspace_id>/notes/<int:note_id>", NoteDetail.as_view(), name="note"),
    path(
        "workspaces/<int:workspace_id>/comments/<int:comment_id>",
        ThreadCommentDetail.as_view(),
        name="comment",
    ),
    path("workspaces/<int:workspace_id>/tasks", TaskViewSet.as_view(), name="tasks"),
    path("workspaces/<int:workspace_id>/tags", TagList.as_view(), name="tags"),
    path("workspaces/<int:workspace_id>/labels", LabelList.as_view(), name="labels"),
    path(
        "workspaces/<int:workspace_id>/attachments",
        AttachmentList.as_view(),
        name="attachments",
    ),
    path("workspaces/<int:workspace_id>/shares", ShareList.as_view(), name="shares"),
]
