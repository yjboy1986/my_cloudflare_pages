// 情報整理チェックリストの記録を Cloudflare KV に保存する受け口。
// Cloudflare Access の内側でのみ到達できる前提で、Access が付ける認証の痕跡
// （メールヘッダー / JWT ヘッダー / CF_Authorization Cookie）のいずれかがあれば許可し、
// どれも無い場合のみ 401 を返す。Pages Functions にはメールヘッダーが渡らない場合が
// あるため、メールヘッダー必須にはしない。
// 例外は握りつぶさず、必ず JSON で {"error": "..."} とステータスを返す。
const KV_KEY = "records-v1";
const EMPTY = { projects: [], current: null };

function jsonResponse(body, status, extraHeaders) {
  return new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status: status || 200,
    headers: Object.assign(
      { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
      extraHeaders || {}
    ),
  });
}

function authSignal(request) {
  if (request.headers.get("Cf-Access-Authenticated-User-Email")) return "email";
  if (request.headers.get("Cf-Access-Jwt-Assertion")) return "jwt";
  const cookie = request.headers.get("Cookie") || "";
  if (/(?:^|;\s*)CF_Authorization=/.test(cookie)) return "cookie";
  return null;
}

export async function onRequest(context) {
  const { request, env } = context;
  try {
    const signal = authSignal(request);
    if (!signal) {
      return jsonResponse({ error: "unauthorized" }, 401);
    }
    const diag = { "X-Checklist-Auth": signal };

    if (!env.CHECKLIST_KV) {
      return jsonResponse({ error: "kv_not_bound" }, 500, diag);
    }

    if (request.method === "GET") {
      const value = await env.CHECKLIST_KV.get(KV_KEY);
      if (!value) return jsonResponse(EMPTY, 200, diag);
      try {
        JSON.parse(value);
        return jsonResponse(value, 200, diag);
      } catch (e) {
        return jsonResponse(EMPTY, 200, diag);
      }
    }

    if (request.method === "PUT") {
      let body;
      try {
        body = await request.text();
        JSON.parse(body);
      } catch (e) {
        return jsonResponse({ error: "invalid_json" }, 400, diag);
      }
      await env.CHECKLIST_KV.put(KV_KEY, body);
      return jsonResponse({ ok: true }, 200, diag);
    }

    return jsonResponse({ error: "method_not_allowed" }, 405, diag);
  } catch (e) {
    return jsonResponse(
      { error: "internal", detail: String((e && e.message) || e) },
      500
    );
  }
}
