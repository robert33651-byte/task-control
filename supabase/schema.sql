-- ============================================================
-- Առաջադրանքների վերահսկում — Supabase schema
-- Запускается целиком в Supabase SQL Editor. Повторный запуск безопасен.
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- ТАБЛИЦЫ ----------

create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  name       text not null,
  role       text not null check (role in ('boss','worker')),
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.tasks (
  id             uuid primary key default gen_random_uuid(),
  title          text not null,
  description    text not null default '',
  due            date,
  assignee       uuid references public.profiles(id) on delete set null,
  created_by     uuid not null references public.profiles(id),
  created_at     timestamptz not null default now(),
  returned_at    timestamptz,
  return_comment text,
  accepted_at    timestamptz
);

create table if not exists public.task_views (
  task_id   uuid not null references public.tasks(id) on delete cascade,
  user_id   uuid not null references public.profiles(id) on delete cascade,
  viewed_at timestamptz not null default now(),
  primary key (task_id, user_id)
);

create table if not exists public.submissions (
  task_id   uuid primary key references public.tasks(id) on delete cascade,
  done_by   uuid not null references public.profiles(id),
  done_at   timestamptz not null default now(),
  file_path text,
  file_name text,
  file_size bigint
);

create table if not exists public.notifications (
  id         bigint generated always as identity primary key,
  recipient  uuid not null references public.profiles(id) on delete cascade,
  title      text not null,
  body       text not null default '',
  url        text,
  created_at timestamptz not null default now(),
  read_at    timestamptz
);

create table if not exists public.push_subscriptions (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references public.profiles(id) on delete cascade,
  endpoint   text not null unique,
  p256dh     text not null,
  auth       text not null,
  created_at timestamptz not null default now()
);

-- ---------- ФУНКЦИИ-ПОМОЩНИКИ ----------

create or replace function public.is_boss() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from profiles where id = auth.uid() and role = 'boss' and active);
$$;

create or replace function public.is_active_user() returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from profiles where id = auth.uid() and active);
$$;

-- Обязательная двухфакторка: без подтверждённого кода из Authenticator (aal2)
-- ни одна политика не даёт доступ к данным.
create or replace function public.aal2() returns boolean
language sql stable as $$
  select coalesce(auth.jwt()->>'aal','') = 'aal2';
$$;

-- ---------- ЗАЩИТА (RLS) ----------

alter table public.profiles           enable row level security;
alter table public.tasks              enable row level security;
alter table public.task_views         enable row level security;
alter table public.submissions        enable row level security;
alter table public.notifications      enable row level security;
alter table public.push_subscriptions enable row level security;

-- profiles: читать могут все активные вошедшие (имена сотрудников); менять — никто
-- (создание/блокировка только через Edge Function с ключом сервера)
drop policy if exists profiles_sel on public.profiles;
create policy profiles_sel on public.profiles for select to authenticated
  using (aal2() and is_active_user());

-- tasks: работник видит только свои и общие; все изменения — только шеф
drop policy if exists tasks_sel on public.tasks;
create policy tasks_sel on public.tasks for select to authenticated
  using (aal2() and is_active_user() and (is_boss() or assignee is null or assignee = auth.uid()));
drop policy if exists tasks_ins on public.tasks;
create policy tasks_ins on public.tasks for insert to authenticated
  with check (aal2() and is_boss() and created_by = auth.uid());
drop policy if exists tasks_upd on public.tasks;
create policy tasks_upd on public.tasks for update to authenticated
  using (aal2() and is_boss()) with check (aal2() and is_boss());
drop policy if exists tasks_del on public.tasks;
create policy tasks_del on public.tasks for delete to authenticated
  using (aal2() and is_boss());

-- task_views: отметка «просмотрено» — только своя и только по доступной задаче;
-- изменить или удалить отметку нельзя никому
drop policy if exists views_sel on public.task_views;
create policy views_sel on public.task_views for select to authenticated
  using (aal2() and is_active_user());
drop policy if exists views_ins on public.task_views;
create policy views_ins on public.task_views for insert to authenticated
  with check (
    aal2() and is_active_user() and user_id = auth.uid()
    and exists(select 1 from tasks t where t.id = task_id
               and (t.assignee is null or t.assignee = auth.uid()))
  );

-- submissions: работник сдаёт только свою работу по доступной непринятой задаче
drop policy if exists subs_sel on public.submissions;
create policy subs_sel on public.submissions for select to authenticated
  using (
    aal2() and is_active_user() and (
      is_boss() or done_by = auth.uid()
      or exists(select 1 from tasks t where t.id = task_id
                and (t.assignee is null or t.assignee = auth.uid()))
    )
  );
drop policy if exists subs_ins on public.submissions;
create policy subs_ins on public.submissions for insert to authenticated
  with check (
    aal2() and is_active_user() and done_by = auth.uid()
    and exists(select 1 from tasks t where t.id = task_id and t.accepted_at is null
               and (t.assignee is null or t.assignee = auth.uid()))
  );
drop policy if exists subs_upd on public.submissions;
create policy subs_upd on public.submissions for update to authenticated
  using (
    aal2() and (
      is_boss()
      or (done_by = auth.uid()
          and exists(select 1 from tasks t where t.id = task_id and t.accepted_at is null))
    )
  )
  with check (aal2() and (is_boss() or done_by = auth.uid()));
drop policy if exists subs_del on public.submissions;
create policy subs_del on public.submissions for delete to authenticated
  using (aal2() and is_boss());

-- notifications: каждый видит и помечает прочитанным только своё;
-- создаются только триггерами
drop policy if exists notif_sel on public.notifications;
create policy notif_sel on public.notifications for select to authenticated
  using (recipient = auth.uid());
drop policy if exists notif_upd on public.notifications;
create policy notif_upd on public.notifications for update to authenticated
  using (recipient = auth.uid()) with check (recipient = auth.uid());

-- push_subscriptions: только свои подписки
drop policy if exists push_sel on public.push_subscriptions;
create policy push_sel on public.push_subscriptions for select to authenticated
  using (user_id = auth.uid());
drop policy if exists push_ins on public.push_subscriptions;
create policy push_ins on public.push_subscriptions for insert to authenticated
  with check (aal2() and user_id = auth.uid());
drop policy if exists push_upd on public.push_subscriptions;
create policy push_upd on public.push_subscriptions for update to authenticated
  using (user_id = auth.uid()) with check (aal2() and user_id = auth.uid());
drop policy if exists push_del on public.push_subscriptions;
create policy push_del on public.push_subscriptions for delete to authenticated
  using (user_id = auth.uid());

-- ---------- ТРИГГЕРЫ УВЕДОМЛЕНИЙ (работают на сервере, обойти нельзя) ----------

-- Новая задача → уведомление исполнителю (или всем работникам)
create or replace function public.notify_task_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.assignee is not null then
    insert into notifications(recipient, title, body)
    values (new.assignee, 'Նոր առաջադրանք', '«' || new.title || '»');
  else
    insert into notifications(recipient, title, body)
    select p.id, 'Նոր առաջադրանք', '«' || new.title || '»'
    from profiles p where p.role = 'worker' and p.active;
  end if;
  return new;
end $$;
drop trigger if exists trg_task_insert on public.tasks;
create trigger trg_task_insert after insert on public.tasks
  for each row execute function public.notify_task_insert();

-- Работа сдана → уведомление всем шефам
create or replace function public.notify_submission() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  t_title text;
  w_name  text;
begin
  select title into t_title from tasks where id = new.task_id;
  select name into w_name from profiles where id = new.done_by;
  insert into notifications(recipient, title, body)
  select p.id, 'Աշխատանքը հանձնված է',
         '«' || coalesce(t_title,'') || '» — ' || coalesce(w_name,'')
  from profiles p where p.role = 'boss' and p.active;
  return new;
end $$;
drop trigger if exists trg_sub_ins on public.submissions;
create trigger trg_sub_ins after insert on public.submissions
  for each row execute function public.notify_submission();
drop trigger if exists trg_sub_upd on public.submissions;
create trigger trg_sub_upd after update of done_at on public.submissions
  for each row execute function public.notify_submission();

-- Принято / возвращено → уведомление исполнителю
create or replace function public.notify_task_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  rcpt uuid;
begin
  rcpt := coalesce((select done_by from submissions where task_id = new.id), new.assignee);
  if new.accepted_at is not null and old.accepted_at is null and rcpt is not null then
    insert into notifications(recipient, title, body)
    values (rcpt, 'Աշխատանքն ընդունված է', '«' || new.title || '»');
  end if;
  if new.returned_at is not null and old.returned_at is distinct from new.returned_at then
    if rcpt is not null then
      insert into notifications(recipient, title, body)
      values (rcpt, 'Վերադարձվել է լրամշակման',
              '«' || new.title || '»' ||
              case when coalesce(new.return_comment,'') <> '' then ' — ' || new.return_comment else '' end);
    end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_task_update on public.tasks;
create trigger trg_task_update after update on public.tasks
  for each row execute function public.notify_task_update();

-- ---------- РЕАЛЬНОЕ ВРЕМЯ ----------
do $$
begin
  begin
    alter publication supabase_realtime add table public.tasks;
  exception when duplicate_object then null; end;
  begin
    alter publication supabase_realtime add table public.task_views;
  exception when duplicate_object then null; end;
  begin
    alter publication supabase_realtime add table public.submissions;
  exception when duplicate_object then null; end;
  begin
    alter publication supabase_realtime add table public.notifications;
  exception when duplicate_object then null; end;
end $$;

-- ---------- ХРАНИЛИЩЕ ФАЙЛОВ (приватное) ----------
insert into storage.buckets (id, name, public)
values ('files', 'files', false)
on conflict (id) do nothing;

-- Путь файла: <task_id>/<user_id>/<имя файла>
drop policy if exists files_ins on storage.objects;
create policy files_ins on storage.objects for insert to authenticated
  with check (
    bucket_id = 'files' and public.aal2()
    and (storage.foldername(name))[2] = auth.uid()::text
    and exists(select 1 from public.tasks t
               where t.id::text = (storage.foldername(name))[1]
                 and t.accepted_at is null
                 and (t.assignee is null or t.assignee = auth.uid()))
  );
drop policy if exists files_sel on storage.objects;
create policy files_sel on storage.objects for select to authenticated
  using (
    bucket_id = 'files' and public.aal2()
    and (public.is_boss() or (storage.foldername(name))[2] = auth.uid()::text)
  );
drop policy if exists files_del on storage.objects;
create policy files_del on storage.objects for delete to authenticated
  using (
    bucket_id = 'files' and public.aal2()
    and (public.is_boss() or (storage.foldername(name))[2] = auth.uid()::text)
  );

-- ============================================================
-- ПОСЛЕ ЗАПУСКА СХЕМЫ: создать профиль шефа.
-- 1) Authentication → Users → Add user → email + пароль (галочка Auto Confirm)
-- 2) Подставить сюда email и имя, выполнить:
--
-- insert into public.profiles (id, name, role)
-- select id, 'Имя Шефа', 'boss' from auth.users where email = 'boss@example.com'
-- on conflict (id) do update set role = 'boss', active = true;
-- ============================================================
-- ============================================================
-- Чат внутри задачи (текст + голосовые). Запускается в SQL Editor, повторный запуск безопасен.
-- ============================================================

create table if not exists public.task_messages (
  id          bigint generated always as identity primary key,
  task_id     uuid not null references public.tasks(id) on delete cascade,
  sender      uuid not null references public.profiles(id),
  body        text not null default '' check (char_length(body) <= 2000),
  audio_path  text,
  audio_secs  int check (audio_secs is null or (audio_secs between 1 and 200)),
  audio_peaks jsonb,
  created_at  timestamptz not null default now(),
  check (body <> '' or audio_path is not null)
);
create index if not exists task_messages_task_idx on public.task_messages(task_id, created_at);
alter table public.task_messages enable row level security;

-- читать: тот, кто видит саму задачу (шеф / назначенный / все при общей задаче)
drop policy if exists msg_sel on public.task_messages;
create policy msg_sel on public.task_messages for select to authenticated
  using (aal2() and is_active_user()
         and exists(select 1 from tasks t where t.id = task_id));

-- писать: только от своего имени, по доступной непринятой задаче; голос — только в своей папке
drop policy if exists msg_ins on public.task_messages;
create policy msg_ins on public.task_messages for insert to authenticated
  with check (
    aal2() and is_active_user() and sender = auth.uid()
    and exists(select 1 from tasks t where t.id = task_id and t.accepted_at is null)
    and (audio_path is null
         or audio_path like task_id::text || '/' || auth.uid()::text || '/v\_%')
  );
-- правок и удаления нет: история неизменна (удаляется только вместе с задачей)

-- Уведомление другой стороне
create or replace function public.notify_message() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  t record;
  s_name text;
  s_role text;
  txt text;
begin
  select * into t from tasks where id = new.task_id;
  select name, role into s_name, s_role from profiles where id = new.sender;
  if new.audio_path is not null then
    txt := '🎤 ' || (new.audio_secs / 60) || ':' || lpad((new.audio_secs % 60)::text, 2, '0');
    if new.body <> '' then txt := txt || ' · ' || left(new.body, 80); end if;
  else
    txt := left(new.body, 120);
  end if;
  txt := coalesce(s_name,'') || '․ ' || txt;
  if s_role = 'boss' then
    if t.assignee is not null then
      insert into notifications(recipient, title, body)
      values (t.assignee, '💬 ' || t.title, txt);
    else
      insert into notifications(recipient, title, body)
      select p.id, '💬 ' || t.title, txt
      from profiles p where p.role = 'worker' and p.active;
    end if;
  else
    insert into notifications(recipient, title, body)
    select p.id, '💬 ' || t.title, txt
    from profiles p where p.role = 'boss' and p.active;
  end if;
  return new;
end $$;
drop trigger if exists trg_msg_ins on public.task_messages;
create trigger trg_msg_ins after insert on public.task_messages
  for each row execute function public.notify_message();

do $$
begin
  begin
    alter publication supabase_realtime add table public.task_messages;
  exception when duplicate_object then null; end;
end $$;

-- Хранилище: шеф может загружать голосовые и по назначенным задачам;
-- голосовые файлы (имя начинается с v_) слышит каждый, кто видит задачу.
drop policy if exists files_ins on storage.objects;
create policy files_ins on storage.objects for insert to authenticated
  with check (
    bucket_id = 'files' and public.aal2()
    and (storage.foldername(name))[2] = auth.uid()::text
    and exists(select 1 from public.tasks t
               where t.id::text = (storage.foldername(name))[1]
                 and t.accepted_at is null
                 and (public.is_boss() or t.assignee is null or t.assignee = auth.uid()))
  );
drop policy if exists files_sel on storage.objects;
create policy files_sel on storage.objects for select to authenticated
  using (
    bucket_id = 'files' and public.aal2()
    and (public.is_boss()
         or (storage.foldername(name))[2] = auth.uid()::text
         or (storage.filename(name) like 'v\_%'
             and exists(select 1 from public.tasks t
                        where t.id::text = (storage.foldername(name))[1])))
  );
