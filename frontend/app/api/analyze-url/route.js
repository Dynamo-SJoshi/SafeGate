const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function POST(request) {
  try {
    const body = await request.json();
    const clientIp = request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "";
    const response = await fetch(`${BACKEND_URL}/analyze-url`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Forwarded-For": clientIp,
      },
      body: JSON.stringify(body),
      cache: "no-store",
    });

    const data = await response.json();
    return Response.json(data, { status: response.status });
  } catch (error) {
    return Response.json(
      { error: "URL analysis proxy failed." },
      { status: 502 }
    );
  }
}

