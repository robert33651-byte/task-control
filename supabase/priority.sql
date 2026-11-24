-- ============================================================
-- Важность задачи: 0 обычная, 1 важная, 2 срочная. Повторный запуск безопасен.
-- ============================================================
alter table public.tasks add column if not exists priority smallint not null default 0;
do $$ begin
  alter table public.tasks add constraint tasks_priority_chk check (priority in (0,1,2));
exception when duplicate_object then null; end $$;

create or replace function public.notify_task_insert() returns trigger
language plpgsql security definer set search_path = public as $$
declare ttl text;
begin
  ttl := case new.priority when 2 then '🔥 Շտապ առաջադրանք' when 1 then '⭐ Կարևոր առաջադրանք' else 'Նոր առաջադրանք' end;
  if new.assignee is not null then
    insert into notifications(recipient, title, body)
    values (new.assignee, ttl, '«' || new.title || '»');
  else
    insert into notifications(recipient, title, body)
    select p.id, ttl, '«' || new.title || '»'
    from profiles p where p.role = 'worker' and p.active;
  end if;
  return new;
end $$;

create or replace function public.notify_task_update() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  rcpt uuid;
  lbl text;
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
  if new.priority is distinct from old.priority and new.accepted_at is null then
    lbl := case new.priority when 2 then '🔥 Շտապ' when 1 then '⭐ Կարևոր' else 'Սովորական' end;
    if new.assignee is not null then
      insert into notifications(recipient, title, body)
      values (new.assignee, 'Կարևորությունը փոխվել է', '«' || new.title || '» — ' || lbl);
    else
      insert into notifications(recipient, title, body)
      select p.id, 'Կարևորությունը փոխվել է', '«' || new.title || '» — ' || lbl
      from profiles p where p.role = 'worker' and p.active;
    end if;
  end if;
  return new;
end $$;
