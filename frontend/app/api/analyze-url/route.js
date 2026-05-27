export async function POST(request) {
  try {
    const body = await request.json();
    const response = await fetch("http://127.0.0.1:8000/analyze-url", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
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

