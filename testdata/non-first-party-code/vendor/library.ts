import express from "express";

const app = express();
const vendorKey = "AKIAIOSFODNN7EXAMPLE";

app.get("/vendor", (_req, res) => res.send(vendorKey));
