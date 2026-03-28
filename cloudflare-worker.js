// Cloudflare Worker — Proxy EdfaPay callbacks to Render server
// انسخ هذا الكود في Cloudflare Workers Dashboard
// رابط الـ Worker: https://icy-frost-0fb7.ziadosama582005.workers.dev

const TARGET_URL = "https://apl-payyyy.onrender.com";

export default {
  async fetch(request) {
    const url = new URL(request.url);

    // Determine target path based on incoming request
    let targetPath;

    if (url.pathname.includes("callback-3ds")) {
      // Forward 3DS callback as-is (e.g., /api/edfa/callback-3ds/xxx)
      targetPath = url.pathname;
    } else {
      // Everything else goes to webhook endpoint
      targetPath = "/api/edfa/webhook";
    }

    const targetUrl = TARGET_URL + targetPath + url.search;

    console.log(`[Proxy] ${request.method} ${url.pathname} → ${targetUrl}`);

    // Clone the request with new URL
    const newRequest = new Request(targetUrl, {
      method: request.method,
      headers: request.headers,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : null,
    });

    try {
      const response = await fetch(newRequest);
      // Return the response from Render server
      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      });
    } catch (err) {
      console.error(`[Proxy Error] ${err.message}`);
      return new Response("Proxy error: " + err.message, { status: 502 });
    }
  },
};
