// Minimal example. Replace with your existing API route to Elastic.
import type { NextApiRequest, NextApiResponse } from "next";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { honey } = req.query;
  const kql = honey === "1" ? 'event.category: "honeypot" OR user.name: canary-*' : '*';
  res.status(200).json({ kql });
}
