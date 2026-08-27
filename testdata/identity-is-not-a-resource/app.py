"""A sibling differential is a claim about one RESOURCE, and two things are not one.

The comparison this corpus is about says: two handlers, one value the caller chose to name
a resource, and only one of them asks whether the caller may have it. The engine cannot
know what check ought to guard an operation and does not have to, because the program
wrote one down on the path beside this one over the very same value.

The value is the whole of it. Measured across ten production repositories the comparison
produced seven findings and an independent reader judged none of them worth reporting, and
all seven were anchored on something no caller picked.

Three were saleor's graphql/context.py, which the negatives below reproduce: the three
functions that BUILD the request's identity, compared against the one that reads it, over
`request` itself. `authenticate(request=request)` is not a guard those three skipped -- it
is where the identity comes FROM, and a function that produces it cannot be required to
have already consumed it. The container is what let the comparison be stated at all: it is
not a value, it is every field the caller sent together with whatever the framework hung
on it, so two functions that both take it have nothing in particular in common.

Four were paperless-ngx, anchored on `request.user`. That is the authentication layer's
answer about who is calling. A handler consulting it has named no resource, and a handler
that does not consult it has skipped nothing a caller could have chosen.
"""
import auth
import reports


def get_report(request):
    # The read path, and the check the program wrote down: a report belongs to exactly
    # one project, and a caller with permission on their own project can name a report
    # in somebody else's.
    report_id = request.GET["report_id"]
    project_id = request.GET["project_id"]
    reports.validate_report_belongs_to_project(report_id, project_id)
    return reports.read(report_id)


def update_report(request):
    # POSITIVE. The same two values out of the same request, and no such question. The
    # finding cites the sibling, because the expected shape is the program's own.
    report_id = request.GET["report_id"]
    project_id = request.GET["project_id"]
    return reports.save(report_id, project_id, request.POST["body"])


def get_user(request):
    # The first negatives' sibling, and the reason the container cannot be the anchor.
    # This is where the identity comes FROM: `authenticate` reads a credential off the
    # request and returns whoever sent it. It does not ask whether an established identity
    # may do something, and there is no resource anywhere in it.
    if not hasattr(request, "_cached_user"):
        request._cached_user = auth.authenticate(request=request)
    return request._cached_user


def set_decoded_auth_token(request):
    # NEGATIVE. saleor/graphql/context.py:70. This extracts the bearer token that the next
    # line decodes. It reads no protected resource and writes none, and it runs BEFORE
    # anybody is authenticated, which is the point of it.
    token = auth.token_from_request(request)
    request.decoded_auth_token = auth.decode(token) if token else None


def set_app_on_context(request):
    # NEGATIVE. saleor/graphql/context.py:78. A context-initialization condition that
    # limits app resolution to the API path and to requests not already carrying an app.
    # `hasattr` is not an operation on anything a caller named.
    if request.path == "/graphql/" and not hasattr(request, "app"):
        request.app = auth.app_for(request)


def set_auth_on_context(request):
    # NEGATIVE. saleor/graphql/context.py:89. The condition distinguishes an
    # already-populated app context; when it holds, the line below deliberately exposes no
    # user at all. That is authentication-context separation, not an unguarded write.
    if hasattr(request, "app") and request.app:
        request.user = None
        return
    request.user = get_user(request)


def get_owned_documents(request):
    # The last negative's sibling. Its check is over `request.user`, which the framework
    # put on the request; no caller chose it.
    return reports.permitted_document_ids(request.user)


def update_document(request):
    # NEGATIVE. paperless-ngx/src/documents/views.py, four times. It takes the same
    # `request.user` and hands it somewhere else, and the difference between the two
    # functions is not a check anybody could have got round: neither one's behaviour turns
    # on a value the caller sent.
    return reports.touch_document(request.user)
