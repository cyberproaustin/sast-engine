from aiohttp import web

from sqli.dao import Student


async def students(request):
    # NEGATIVE. Reading the query is not a weakness; where it goes is.
    return web.Response(text=str(request.query.get("sort")))


async def create_student(request):
    # POSITIVE. The body is read with a METHOD, because an aiohttp body is a coroutine
    # and there is no property to reach for -- so the property list that covers Flask
    # covers none of this.
    data = await request.post()
    await Student.create(request.app["db"], data["name"])
    return web.Response(text="ok")
