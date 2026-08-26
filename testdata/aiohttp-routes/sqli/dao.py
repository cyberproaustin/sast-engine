class Student:
    @staticmethod
    async def create(conn, name):
        # POSITIVE. Two files from the handler, behind a class the caller imported --
        # which is how a data-access layer is written, and which left every such call
        # external until the method was registered under the name an importer uses.
        q = "INSERT INTO students (name) VALUES ('%(name)s')" % {"name": name}
        async with conn.cursor() as cur:
            await cur.execute(q)
