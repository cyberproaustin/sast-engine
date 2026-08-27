/* One statically absent capture and the neighboring forms that exist.

The positive is PDF.js's exact shape: the regex validates an origin but captures none,
then the match result is indexed at one. Whether the match object itself was checked is
irrelevant to that proof -- element one is undefined on every successful match too.
*/

function brokenOrigin(parentUrl) {
  const origin = /^[^:]+:\/\/[^/]+/.exec(parentUrl);
  // POSITIVE. Group zero is the whole match; this literal defines no group one.
  return origin ? origin[1] : parentUrl;
}

function capturedOrigin(parentUrl) {
  // NEGATIVE. One pair of capturing parentheses makes index one a real group.
  const origin = /^([^:]+):\/\/[^/]+/.exec(parentUrl);
  return origin ? origin[1] : parentUrl;
}

function wholeMatch(parentUrl) {
  // NEGATIVE. Index zero is always the complete match, even with no capture groups.
  const origin = /^[^:]+:\/\/[^/]+/.exec(parentUrl);
  return origin ? origin[0] : parentUrl;
}

function namedCapture(parentUrl) {
  // NEGATIVE. Named groups still occupy numeric capture slots.
  const origin = /^(?<scheme>[^:]+):\/\/[^/]+/.exec(parentUrl);
  return origin ? origin[1] : parentUrl;
}

function dynamicPattern(parentUrl, pattern) {
  // NEGATIVE. A runtime pattern has no arity the source fixes, so the rule declines.
  const origin = pattern.exec(parentUrl);
  return origin ? origin[7] : parentUrl;
}

function reassignedResult(parentUrl) {
  // NEGATIVE. The latest assignment defines enough groups for this read.
  let match = /(one)/.exec(parentUrl);
  match = /(one)(two)(three)/.exec(parentUrl);
  return match ? match[3] : parentUrl;
}

module.exports = {
  brokenOrigin,
  capturedOrigin,
  wholeMatch,
  namedCapture,
  dynamicPattern,
  reassignedResult,
};
