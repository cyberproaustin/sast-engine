// The third positive, and the same hole read from the other end: the restriction is built
// and then abandoned before the line that attaches it.
//
// `addAccessPolicyFilters` returns nothing, so the predicate it pushes onto the builder is
// the only thing it does. The malformed-criteria branch complains and leaves, and the
// disjunction it had already accumulated is dropped -- which does not narrow the search,
// it widens it.
//
// The `return` eight lines below it is the negative that keeps this rule honest. It
// abandons the same accumulator through the same graph shape and is correct: a policy that
// names no criteria allows everything, so a disjunction with an already-satisfied term
// belongs on the floor. Nothing separates the two but the complaint.
import { Condition, Disjunction, logger, parseCriteria } from "./store";

type Policy = { resourceType: string; compartment?: string; criteria?: string };
type Builder = { predicate: { expressions: unknown[] } };

export function addAccessPolicyFilters(builder: Builder, resourceType: string, policies: Policy[]) {
  const expressions: unknown[] = [];

  for (const policy of policies) {
    if (policy.resourceType !== resourceType) {
      continue;
    }
    if (policy.compartment) {
      expressions.push(new Condition("compartments", policy.compartment));
    } else if (policy.criteria) {
      if (!policy.criteria.startsWith(policy.resourceType + "?")) {
        logger.warn("invalid access policy criteria", { criteria: policy.criteria });
        return;
      }
      expressions.push(parseCriteria(policy.criteria));
    } else {
      // A policy with neither compartment nor criteria permits the whole resource type,
      // so the disjunction is already satisfied and dropping it is the right answer.
      return;
    }
  }

  if (expressions.length > 0) {
    builder.predicate.expressions.push(new Disjunction(expressions));
  }
}
