// Handlers live in their own module and are registered by name, which is how real
// Express applications are usually organized.

export function listOrders(req, res): void {
  res.json({ orders: [] });
}

export function getOrder(req, res): void {
  res.json({ id: req.params.id });
}

export function createOrder(req, res): void {
  res.status(201).json({ id: "new" });
}

export function deleteOrder(req, res): void {
  res.status(204).send();
}

export function healthCheck(req, res): void {
  res.json({ ok: true });
}

export function adminStats(req, res): void {
  res.json({ total: 0 });
}
