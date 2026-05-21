export async function GET() {
  try {
    const response = await fetch("http://127.0.0.1:8000/health", {
      cache: "no-store",
    });
    const data = await response.json();

    return Response.json(
      {
        backend: data,
        status: response.ok ? "ok" : "error",
      },
      { status: response.ok ? 200 : 502 }
    );
  } catch (error) {
    return Response.json(
      {
        status: "offline",
        error: "Backend health check failed.",
      },
      { status: 502 }
    );
  }
}

