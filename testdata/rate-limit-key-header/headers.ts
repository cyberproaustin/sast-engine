// The header list in a module of its own, which is where reactive-resume keeps it and
// which is the reason the value graph alone was not enough: neither frontend links an
// imported constant to the module that declares it, so the reference is a name with
// nothing flowing into it and a backwards walk stops there.
export const TRUSTED_IP_HEADERS = [
  "CF-Connecting-IP",
  "CF-Connecting-IPv6",
  "True-Client-IP",
  "X-Forwarded-For",
  "X-Real-IP",
];
