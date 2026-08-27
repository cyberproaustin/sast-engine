def incr_sliding_window(bucket):
    return bucket


def filter_request(request):
    return incr_sliding_window(request.remote_addr)
