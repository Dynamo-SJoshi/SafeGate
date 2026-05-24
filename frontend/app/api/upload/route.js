export async function POST(request) {
  try {
    const incomingFormData = await request.formData();
    const file = incomingFormData.get("file");

    if (!file) {
      return Response.json({ error: "No file provided." }, { status: 400 });
    }

    const forwardFormData = new FormData();
    forwardFormData.append("file", file);

    const backendResponse = await fetch("http://127.0.0.1:8000/upload", {
      method: "POST",
      body: forwardFormData,
      cache: "no-store",
    });

    const data = await backendResponse.json();

    return Response.json(data, { status: backendResponse.status });
  } catch (error) {
    return Response.json(
      {
        error: "Upload proxy failed.",
      },
      { status: 502 }
    );
  }
}

