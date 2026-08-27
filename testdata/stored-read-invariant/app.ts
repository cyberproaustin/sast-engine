import express from "express";

const app = express();
const SAFE_SLUG = /^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*$/;

interface Page {
  slug: string;
  reload(): Promise<void>;
}

// These names deliberately use an ORM's read/write vocabulary. The implementation is
// immaterial to the boundary under test: one request writes `slug`, another reads it.
declare const pages: {
  create(value: { slug: string }): Promise<void>;
  findOne(where: { id: string }): Promise<Page>;
};

app.post("/pages", async (req, res) => {
  await pages.create({ slug: req.body.slug });
  return res.send("created");
});

app.get("/pages/:id/same-value", async (req, res) => {
  const page = await pages.findOne({ id: req.params.id });
  const slug = page.slug;
  // NEGATIVE. The exact value checked is the exact value sent.
  if (!slug.match(SAFE_SLUG)) return res.status(400).send("invalid slug");
  return res.send(slug);
});

app.get("/pages/:id/fresh-read", async (req, res) => {
  const page = await pages.findOne({ id: req.params.id });
  // POSITIVE. This establishes an invariant on this read, not on the column forever.
  if (!page.slug.match(SAFE_SLUG)) return res.status(400).send("invalid slug");
  await page.reload();
  return res.send(page.slug);
});

export default app;
