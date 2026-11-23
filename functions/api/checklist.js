// 情報整理チェックリストの記録を Cloudflare KV に保存する受け口。
// Cloudflare Access の内側でのみ到達でき、認証メールヘッダーが無い要求は弾く。
const KV_KEY = "records-v1";
const EMPTY = { projects: [], current: null };

function jsonResponse(body, status) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

export async function onRequest(context) {
  const { request, env } = context;

  const email = request.headers.get("Cf-Access-Authenticated-User-Email");
  if (!email) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  if (!env.CHECKLIST_KV) {
    return jsonResponse({ error: "kv_not_bound" }, 500);
  }

  if (request.method === "GET") {
    const value = await env.CHECKLIST_KV.get(KV_KEY);
    if (!value) return jsonResponse(EMPTY);
    try {
      JSON.parse(value);
      return jsonResponse(value);
    } catch (e) {
      return jsonResponse(EMPTY);
    }
  }

  if (request.method === "PUT") {
    let body;
    try {
      body = await request.text();
      JSON.parse(body);
    } catch (e) {
      return jsonResponse({ error: "invalid_json" }, 400);
    }
    await env.CHECKLIST_KV.put(KV_KEY, body);
    return jsonResponse({ ok: true });
  }

  return jsonResponse({ error: "method_not_allowed" }, 405);
}
