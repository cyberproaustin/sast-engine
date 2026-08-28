"""The data layer, defined here so every hop resolves -- the same choice express-idor
makes about Prisma."""


class NoteStore:
    def delete(self, note_id):
        return note_id

    def delete_for_owner(self, note_id, owner_id):
        return note_id, owner_id


notes = NoteStore()
