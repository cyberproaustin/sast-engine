import * as endpointsObject from "./endpoint-list.ts";

export interface IEndpoint {
  name: string;
  meta: { requireCredential: boolean };
}

// The re-export table reshaped into a list of descriptions. The KEY becomes `name`, and
// `name` is what the registration below puts in the URL.
const endpoints: IEndpoint[] = Object.entries(endpointsObject).map(([name, ep]) => {
  return { name: name, meta: ep.meta };
});

export default endpoints;
