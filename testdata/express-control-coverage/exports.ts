// NEGATIVE: three handlers, one signature, and the call they share is a LOOKUP.
//
// The shape is the broadcast positive exactly -- two peers gate `getSerializer` behind a
// permission question and the third does not -- and it is not a finding, because fetching
// a serializer does nothing to any record. Measured: taking a retrieval for an operation
// made twelve unrelated view classes of one paperless-ngx module peers of each other and
// produced twelve false findings, every one of this shape.
import { permissions, serializerFor } from "./store";

type Req = { body: { kind: string; ids: number[] } };

export class ExportViews {
  getSerializer(kind: string) {
    return serializerFor(kind);
  }

  async exportCsv(req: Req) {
    if (await permissions.permittedKinds(req.body.kind)) {
      return this.getSerializer(req.body.kind);
    }
    return null;
  }

  async exportJson(req: Req) {
    return this.getSerializer(req.body.kind);
  }

  async exportXml(req: Req) {
    if (await permissions.permittedKinds(req.body.kind)) {
      return this.getSerializer(req.body.kind);
    }
    return null;
  }
}
