// The second positive, and the second spelling of "the path beside it": sibling handlers
// rather than sibling branches.
//
// Three methods, one dispatcher, one signature, one call. Two of them ask whether this
// subscriber may see the event before sending it; `documentsDeleted` sends it. Nothing
// about the deletion event makes it less private than the update event -- they carry the
// same document identities to the same socket.
import { permissions } from "./store";

type Event = { data: { documentIds: number[]; owner: number } };

export class StatusConsumer {
  private socket: { write(text: string): void } = { write: () => undefined };

  async send(payload: string) {
    this.socket.write(payload);
  }

  async canViewEvent(data: Event["data"]) {
    return permissions.visibleTo(data.owner);
  }

  async statusUpdate(event: Event) {
    if (await this.canViewEvent(event.data)) {
      await this.send(JSON.stringify(event));
    }
  }

  async documentsDeleted(event: Event) {
    await this.send(JSON.stringify(event));
  }

  async documentUpdated(event: Event) {
    if (await this.canViewEvent(event.data)) {
      await this.send(JSON.stringify(event));
    }
  }
}
