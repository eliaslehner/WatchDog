// Server-side API route — env usage here is fine
export default function handler(req, res) {
  const dbUrl = process.env.DATABASE_URL;
  res.status(200).json({ status: 'ok' });
}
