# Առաջադրանքների վերահսկում — контроль задач (Supabase + GitHub Pages)

Приложение для постановки задач от шефа бухгалтерам: отметки «просмотрено»,
сдача работы с Excel-файлом, приёмка шефом, уведомления в реальном времени
и push-уведомления (Android у шефа, ПК у работников).

## Состав

```
public/                 — сайт (кладётся в GitHub Pages)
  index.html            — всё приложение (армянский интерфейс)
  sw.js                 — service worker (push-уведомления)
  manifest.json         — PWA-манифест (установка на телефон)
  icons/                — иконки
supabase/
  schema.sql            — таблицы, защита (RLS), триггеры уведомлений, хранилище
  vapid-keys.txt        — ключи push (приватный — только в секреты функции!)
  functions/send-push/  — Edge Function: рассылка push по webhook
  functions/admin-users/— Edge Function: управление сотрудниками (только шеф)
scripts/                — генераторы ключей и иконок (уже выполнены)
```

## Безопасность

- Вход: email + пароль + код Google Authenticator (TOTP, обязателен).
  Без 2FA (aal2) ни одна таблица не отдаёт ни строки — проверено тестами.
- Работник не может: создать/изменить/принять/удалить задачу, увидеть чужие
  задачи/файлы/уведомления, подделать отметку просмотра, пересдать после приёмки.
- Файлы в приватном хранилище, скачивание по временным подписанным ссылкам.
- Создание/блокировка сотрудников — только шеф, через Edge Function.
- На телефоне: PIN при открытии. На ПК: автовыход через 30 минут бездействия.

## Установка (однократно)

1. **Supabase → SQL Editor**: выполнить `supabase/schema.sql` целиком.
2. **Authentication → Sign In / Up**: выключить "Allow new users to sign up".
   **Multi-Factor** — TOTP включён (по умолчанию включён).
3. **Создать шефа**: Authentication → Users → Add user (email+пароль,
   Auto Confirm), затем в SQL Editor выполнить insert из конца schema.sql.
4. **Edge Functions**: создать `admin-users` и `send-push` (код из
   `supabase/functions/...`). У `send-push` выключить "Verify JWT".
5. **Secrets** (Edge Functions → Secrets): добавить
   `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` (из vapid-keys.txt) и
   `WEBHOOK_SECRET` (любая длинная случайная строка).
6. **Database → Webhooks**: создать webhook на таблицу `notifications`,
   событие INSERT, тип HTTP Request → URL функции send-push
   (`https://<project>.supabase.co/functions/v1/send-push`),
   заголовок `x-webhook-secret: <WEBHOOK_SECRET>`.
7. **В `public/index.html`** вписать SUPABASE_URL и SUPABASE_ANON_KEY
   (Settings → API).
8. **GitHub**: залить содержимое `public/` в репозиторий, включить
   Pages (Settings → Pages → Deploy from branch → main → / (root)).

## Использование

- Адрес сайта: `https://<логин>.github.io/<репозиторий>/`
- Шеф на Android: открыть в Chrome → меню → «Добавить на главный экран»,
  в настройках приложения (⚙️) включить Push.
- Работники на ПК: открыть сайт, разрешить уведомления (⚙️ → Push).
  Уведомления приходят даже при закрытой вкладке, пока запущен браузер.
- Первый вход каждого сотрудника: email+пароль от шефа → сканировать QR
  в Google Authenticator → ввести код. Дальше — пароль + код.
- Потерян телефон с Authenticator: шеф в панели «Аշխատакիցներ» жмёт
  «2FA սկզբ.» — при следующем входе будет выдан новый QR.
