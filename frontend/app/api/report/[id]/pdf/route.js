const BACKEND_URL = process.env.BACKEND_URL || "http://127.0.0.1:8000";

export async function GET(request, { params }) {
  const { id } = await params;
  try {
    const backendResponse = await fetch(`${BACKEND_URL}/report/${id}/pdf`, {
      method: "GET",
      cache: "no-store",
    });

    if (!backendResponse.ok) {
      return Response.json(
        { error: "Failed to fetch PDF from backend" },
        { status: backendResponse.status }
      );
    }

    const pdfBuffer = await backendResponse.arrayBuffer();
    return new Response(pdfBuffer, {
      status: 200,
      headers: {
        "Content-Type": "application/pdf",
        "Content-Disposition": `inline; filename="SafeGate_Report_${id}.pdf"`
      }
    });
  } catch (error) {
    return Response.json(
      { error: "Report PDF proxy failed." },
      { status: 502 }
    );
  }
}
