const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function GET() {
  return Response.json({ url: BACKEND_URL });
}
