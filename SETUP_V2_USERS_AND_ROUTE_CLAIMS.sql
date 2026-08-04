create table if not exists public.app_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  full_name text not null default 'Employee',
  role text not null default 'crew'
    check (role in ('admin','supervisor','crew')),
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.handle_new_app_user()
returns trigger
language plpgsql
security definer set search_path=public
as $$
begin
  insert into public.app_profiles(id,email,full_name,role)
  values(
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name',split_part(new.email,'@',1)),
    coalesce(new.raw_user_meta_data->>'role','crew')
  )
  on conflict(id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_app_profile on auth.users;
create trigger on_auth_user_created_app_profile
after insert on auth.users
for each row execute function public.handle_new_app_user();

insert into public.app_profiles(id,email,full_name,role)
select id,email,
       coalesce(raw_user_meta_data->>'full_name',split_part(email,'@',1)),
       coalesce(raw_user_meta_data->>'role','crew')
from auth.users
on conflict(id) do nothing;

create table if not exists public.route_claims (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  user_name text not null,
  route text not null,
  direction text not null,
  start_sign_no text,
  start_sign_id text,
  current_sign_no text,
  status text not null default 'active'
    check (status in ('active','released','completed')),
  started_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists one_active_route_per_user
on public.route_claims(user_id) where status='active';

create table if not exists public.sign_user_progress (
  sign_id text primary key,
  sign_no text not null,
  route text not null,
  roadway_side text,
  status text not null
    check (status in ('installed','not_installed','needs_attention','unable_access')),
  completed_by uuid references auth.users(id),
  completed_by_name text,
  completed_at timestamptz not null default now(),
  notes text,
  out_of_sequence boolean not null default false,
  updated_at timestamptz not null default now()
);

alter table public.app_profiles enable row level security;
alter table public.route_claims enable row level security;
alter table public.sign_user_progress enable row level security;

drop policy if exists "profiles readable by signed users" on public.app_profiles;
create policy "profiles readable by signed users"
on public.app_profiles for select to authenticated using (true);

drop policy if exists "users update own profile" on public.app_profiles;
create policy "users update own profile"
on public.app_profiles for update to authenticated
using (id=auth.uid()) with check (id=auth.uid());

drop policy if exists "claims readable by signed users" on public.route_claims;
create policy "claims readable by signed users"
on public.route_claims for select to authenticated using (true);

drop policy if exists "users create own claims" on public.route_claims;
create policy "users create own claims"
on public.route_claims for insert to authenticated
with check (user_id=auth.uid());

drop policy if exists "users update own claims" on public.route_claims;
create policy "users update own claims"
on public.route_claims for update to authenticated
using (user_id=auth.uid()) with check (user_id=auth.uid());

drop policy if exists "progress readable by signed users" on public.sign_user_progress;
create policy "progress readable by signed users"
on public.sign_user_progress for select to authenticated using (true);

drop policy if exists "signed users write progress" on public.sign_user_progress;
create policy "signed users write progress"
on public.sign_user_progress for insert to authenticated
with check (completed_by=auth.uid());

drop policy if exists "signed users update progress" on public.sign_user_progress;
create policy "signed users update progress"
on public.sign_user_progress for update to authenticated
using (true) with check (completed_by=auth.uid());

grant select on public.app_profiles to authenticated;
grant select,insert,update on public.route_claims to authenticated;
grant select,insert,update on public.sign_user_progress to authenticated;