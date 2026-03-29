export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method !== 'POST') {
      return new Response('Webhook proxy is running.', { status: 200 });
    }

    try {
      let targetUrl;

      if (url.pathname.includes('callback-3ds')) {
        targetUrl = 'https://apl-payyyy.onrender.com/api/edfa' + url.pathname.substring(url.pathname.indexOf('/callback-3ds'));
      } else {
        targetUrl = 'https://apl-payyyy.onrender.com/api/edfa/webhook';
      }

      const body = await request.arrayBuffer();

      const cleanHeaders = new Headers();
      cleanHeaders.set('Content-Type', request.headers.get('Content-Type') || 'application/x-www-form-urlencoded');
      cleanHeaders.set('Content-Length', body.byteLength.toString());

      const forwardRequest = await fetch(targetUrl, {
        method: 'POST',
        body: body,
        headers: cleanHeaders
      });

      const responseText = await forwardRequest.text();
      return new Response(responseText, {
        status: forwardRequest.status,
        headers: forwardRequest.headers
      });

    } catch (error) {
      console.error("Error:", error);
      return new Response('Proxy error', { status: 500 });
    }
  }
};
