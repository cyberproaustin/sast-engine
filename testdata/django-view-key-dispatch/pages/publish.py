"""The class the key `publish` resolves to. Its verb is on a base this program defines."""

from common.generic import PublishView


class PagePublishView(PublishView):
    model = "Page"
