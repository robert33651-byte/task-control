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
