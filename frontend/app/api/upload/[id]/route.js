const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(request, { params }) {
  const { id } = params;
  try {
    const backendResponse = await fetch(`${BACKEND_URL}/upload/${id}`, {
      method: "GET",
      cache: "no-store",
    });

    const data = await backendResponse.json();
    return Response.json(data, { status: backendResponse.status });
  } catch (error) {
    return Response.json(
      { error: "Upload status proxy failed." },
      { status: 502 }
    );
  }
}
