export async function GET(request) {
  return Response.json({
    host: request.headers.get('host') || '',
    x_forwarded_host: request.headers.get('x-forwarded-host') || '',
    x_forwarded_proto: request.headers.get('x-forwarded-proto') || ''
  });
}
