// Edge Function: send-push
// Вызывается Database Webhook'ом при INSERT в таблицу notifications.
// Шлёт Web Push на все подписки получателя. Мёртвые подписки удаляет.
//
// Секреты (Edge Functions → Secrets):
//   WEBHOOK_SECRET    — тот же, что в заголовке x-webhook-secret у webhook'а
//   VAPID_PUBLIC_KEY  — публичный VAPID-ключ
//   VAPID_PRIVATE_KEY — приватный VAPID-ключ
// SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY подставляются автоматически.
//
// В настройках функции отключить проверку JWT (Verify JWT = off) —
// запрос приходит от webhook'а, защита — секретным заголовком.

import { createClient } from "npm:@supabase/supabase-js@2";
import webpush from "npm:web-push@3.6.7";

Deno.serve(async (req) => {
  try {
    const secret = Deno.env.get("WEBHOOK_SECRET") ?? "";
    if (!secret || req.headers.get("x-webhook-secret") !== secret) {
      return new Response("forbidden", { status: 403 });
    }

    const payload = await req.json();
    const rec = payload?.record;
    if (!rec?.recipient || !rec?.title) {
      return new Response("bad payload", { status: 400 });
    }

    const admin = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
    );

    const { data: subs, error } = await admin
      .from("push_subscriptions")
      .select("id, endpoint, p256dh, auth")
      .eq("user_id", rec.recipient);
    if (error) return new Response("db error", { status: 500 });
    if (!subs || subs.length === 0) return new Response("no subs", { status: 200 });

    webpush.setVapidDetails(
      "mailto:admin@localhost.local",
      Deno.env.get("VAPID_PUBLIC_KEY")!,
      Deno.env.get("VAPID_PRIVATE_KEY")!,
    );

    const body = JSON.stringify({
      title: rec.title,
      body: rec.body ?? "",
      url: rec.url ?? "./",
    });

    const dead: number[] = [];
    await Promise.all(subs.map(async (s) => {
      try {
        await webpush.sendNotification(
          { endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } },
          body,
          { TTL: 86400 },
        );
      } catch (e) {
        const code = (e as { statusCode?: number })?.statusCode;
        if (code === 404 || code === 410) dead.push(s.id);
      }
    }));

    if (dead.length) {
      await admin.from("push_subscriptions").delete().in("id", dead);
    }
    return new Response(JSON.stringify({ sent: subs.length - dead.length }), {
      headers: { "content-type": "application/json" },
    });
  } catch {
    return new Response("error", { status: 500 });
  }
});
