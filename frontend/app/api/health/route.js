const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function GET() {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

  try {
    const response = await fetch(`${BACKEND_URL}/health`, {
      cache: "no-store",
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    const data = await response.json();

    return Response.json(
      {
        backend: data,
        status: response.ok ? "ok" : "error",
      },
      { status: response.ok ? 200 : 502 }
    );
  } catch (error) {
    clearTimeout(timeoutId);
    return Response.json(
      {
        status: "offline",
        error: "Backend health check failed or timed out.",
      },
      { status: 502 }
    );
  }
}

