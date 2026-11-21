// Edge Function: admin-users
// Управление сотрудниками. Вызывается только из приложения.
// Выполняет действие ТОЛЬКО если вызвавший: активный шеф, вошедший с 2FA (aal2).
//
// Действия:
//   { action:"create",     email, password, name, role }  — создать сотрудника
//   { action:"deactivate", uid }                          — заблокировать
//   { action:"reactivate", uid }                          — разблокировать
//   { action:"resetpw",    uid, password }                — сменить пароль (сбрасывает сессии при следующем обновлении токена)
//   { action:"resetmfa",   uid }                          — сбросить 2FA (потерян телефон)
//
// Verify JWT = ON (по умолчанию). Секретов не требует:
// SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY подставляются автоматически.

import { createClient } from "npm:@supabase/supabase-js@2";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (obj: unknown, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });

function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    const s = part.replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(s));
  } catch { return null; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    const token = authHeader.replace(/^Bearer\s+/i, "");
    if (!token) return json({ error: "no auth" }, 401);

    // Проверка 2FA: в токене должен стоять aal2
    const claims = b64urlJson(token.split(".")[1] ?? "");
    if (!claims || claims["aal"] !== "aal2") {
      return json({ error: "requires 2FA (aal2)" }, 403);
    }

    const url = Deno.env.get("SUPABASE_URL")!;
    const admin = createClient(url, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // Кто вызывает?
    const { data: userData, error: uerr } = await admin.auth.getUser(token);
    if (uerr || !userData?.user) return json({ error: "bad token" }, 401);
    const callerId = userData.user.id;

    const { data: callerProfile } = await admin
      .from("profiles").select("role, active").eq("id", callerId).single();
    if (!callerProfile || callerProfile.role !== "boss" || !callerProfile.active) {
      return json({ error: "not allowed" }, 403);
    }

    const body = await req.json();
    const action = String(body?.action ?? "");

    if (action === "create") {
      const email = String(body.email ?? "").trim().toLowerCase();
      const password = String(body.password ?? "");
      const name = String(body.name ?? "").trim();
      const role = body.role === "boss" ? "boss" : "worker";
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "bad email" }, 400);
      if (password.length < 8) return json({ error: "password too short" }, 400);
      if (!name) return json({ error: "no name" }, 400);

      const { data: created, error } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
      });
      if (error || !created?.user) return json({ error: error?.message ?? "create failed" }, 400);
      const { error: perr } = await admin.from("profiles").insert({
        id: created.user.id, name, role,
      });
      if (perr) {
        await admin.auth.admin.deleteUser(created.user.id);
        return json({ error: perr.message }, 400);
      }
      return json({ ok: true, uid: created.user.id });
    }

    const uid = String(body?.uid ?? "");
    if (!uid) return json({ error: "no uid" }, 400);
    if (uid === callerId && (action === "deactivate")) {
      return json({ error: "cannot deactivate yourself" }, 400);
    }

    if (action === "deactivate") {
      const { error } = await admin.auth.admin.updateUserById(uid, { ban_duration: "876000h" });
      if (error) return json({ error: error.message }, 400);
      await admin.from("profiles").update({ active: false }).eq("id", uid);
      await admin.from("push_subscriptions").delete().eq("user_id", uid);
      return json({ ok: true });
    }
    if (action === "reactivate") {
      const { error } = await admin.auth.admin.updateUserById(uid, { ban_duration: "none" });
      if (error) return json({ error: error.message }, 400);
      await admin.from("profiles").update({ active: true }).eq("id", uid);
      return json({ ok: true });
    }
    if (action === "resetpw") {
      const password = String(body.password ?? "");
      if (password.length < 8) return json({ error: "password too short" }, 400);
      const { error } = await admin.auth.admin.updateUserById(uid, { password });
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }
    if (action === "resetmfa") {
      const { data: factors } = await admin.auth.admin.mfa.listFactors({ userId: uid });
      const list = factors?.factors ?? [];
      for (const f of list) {
        await admin.auth.admin.mfa.deleteFactor({ userId: uid, id: f.id });
      }
      return json({ ok: true, removed: list.length });
    }

    return json({ error: "unknown action" }, 400);
  } catch {
    return json({ error: "server error" }, 500);
  }
});
