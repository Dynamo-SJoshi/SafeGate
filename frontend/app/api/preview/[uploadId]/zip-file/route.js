const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(request, { params }) {
  try {
    const { uploadId } = params;
    const { searchParams } = new URL(request.url);
    const filePath = searchParams.get("file_path");

    if (!filePath) {
      return Response.json({ error: "Missing file_path query parameter." }, { status: 400 });
    }

    const response = await fetch(
      `${BACKEND_URL}/preview/${uploadId}/zip-file?file_path=${encodeURIComponent(filePath)}`,
      { cache: "no-store" }
    );

    const data = await response.json();
    return Response.json(data, { status: response.status });
  } catch (error) {
    return Response.json({ error: "ZIP file preview proxy failed." }, { status: 502 });
  }
}
