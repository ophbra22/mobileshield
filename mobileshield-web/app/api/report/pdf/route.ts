/** Reports are retired: analysis is a per-request workflow with no saved scans. */
export async function POST(_request: Request) {
  return Response.json({ detail: 'reports_unavailable' }, { status: 410, headers: { 'Cache-Control': 'no-store' } });
}
