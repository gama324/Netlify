# Netlify-- LocalFix Supabase starter schema
-- Apply in Supabase SQL Editor. Review RLS policies before production use.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'customer' check (role in ('customer','provider','admin')),
  created_at timestamptz not null default now()
);

create table if not exists public.provider_profiles (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  display_name text not null,
  service_category text not null,
  location_text text not null,
  bio text not null default '',
  starting_price_ngn numeric(12,2) check (starting_price_ngn is null or starting_price_ngn >= 0),
  is_listed boolean not null default false,
  is_verified boolean not null default false,
  is_premium boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid not null references public.profiles(id) on delete restrict,
  provider_id uuid references public.profiles(id) on delete set null,
  service_category text not null,
  title text not null,
  description text not null,
  location_text text not null,
  budget_ngn numeric(12,2) check (budget_ngn is null or budget_ngn >= 0),
  agreed_amount_ngn numeric(12,2) check (agreed_amount_ngn is null or agreed_amount_ngn >= 0),
  status text not null default 'pending' check (status in ('pending','accepted','in_progress','completed','cancelled','rejected')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid not null unique references public.bookings(id) on delete restrict,
  customer_id uuid not null references public.profiles(id) on delete restrict,
  provider_id uuid references public.profiles(id) on delete set null,
  amount_ngn numeric(12,2) not null check (amount_ngn > 0),
  commission_rate numeric(5,4) not null check (commission_rate >= 0 and commission_rate <= 1),
  commission_ngn numeric(12,2) not null check (commission_ngn >= 0),
  currency text not null default 'NGN',
  payment_provider text,
  provider_reference text unique,
  status text not null default 'pending' check (status in ('pending','paid','failed','refunded')),
  created_at timestamptz not null default now()
);

create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.provider_profiles enable row level security;
alter table public.bookings enable row level security;
alter table public.payments enable row level security;
alter table public.admin_users enable row level security;

-- Admin status comes from a separately controlled table, never from user-editable metadata.
create or replace function public.is_localfix_admin()
returns boolean language sql stable security definer set search_path = public
as $$ select exists(select 1 from public.admin_users where user_id = auth.uid()); $$;
revoke all on function public.is_localfix_admin() from public;
grant execute on function public.is_localfix_admin() to authenticated;

create policy "Profiles readable by owner or admin" on public.profiles
for select to authenticated using (id = auth.uid() or public.is_localfix_admin());
create policy "Users create own customer/provider profile" on public.profiles
for insert to authenticated with check (id = auth.uid() and role in ('customer','provider'));
create policy "Users update own non-admin profile" on public.profiles
for update to authenticated using (id = auth.uid() and role <> 'admin') with check (id = auth.uid() and role <> 'admin');
create policy "Admins manage profiles" on public.profiles
for all to authenticated using (public.is_localfix_admin()) with check (public.is_localfix_admin());

create policy "Listed provider profiles are public" on public.provider_profiles
for select to anon, authenticated using (is_listed = true or user_id = auth.uid() or public.is_localfix_admin());
create policy "Provider creates own profile" on public.provider_profiles
for insert to authenticated with check (user_id = auth.uid() and exists(select 1 from public.profiles p where p.id = auth.uid() and p.role = 'provider'));
create policy "Provider updates own profile without changing admin flags" on public.provider_profiles
for update to authenticated using (user_id = auth.uid() or public.is_localfix_admin())
with check (public.is_localfix_admin() or (user_id = auth.uid() and is_verified = false and is_listed = false and is_premium = false));
create policy "Admin manages provider profiles" on public.provider_profiles
for all to authenticated using (public.is_localfix_admin()) with check (public.is_localfix_admin());

create policy "Customers and assigned providers can read bookings" on public.bookings
for select to authenticated using (customer_id = auth.uid() or provider_id = auth.uid() or public.is_localfix_admin());
create policy "Customers create own booking" on public.bookings
for insert to authenticated with check (customer_id = auth.uid() and provider_id is null and status = 'pending');
create policy "Customer can cancel own pending booking" on public.bookings
for update to authenticated using (customer_id = auth.uid() and status = 'pending')
with check (customer_id = auth.uid() and status in ('pending','cancelled'));
create policy "Assigned provider can update job status" on public.bookings
for update to authenticated using (provider_id = auth.uid() or public.is_localfix_admin())
with check (provider_id = auth.uid() or public.is_localfix_admin());
create policy "Admins manage bookings" on public.bookings
for all to authenticated using (public.is_localfix_admin()) with check (public.is_localfix_admin());

create policy "Payment records visible to parties or admin" on public.payments
for select to authenticated using (customer_id = auth.uid() or provider_id = auth.uid() or public.is_localfix_admin());
-- Deliberately no client insert/update policy on payments. Payment rows must be created by a trusted server
-- after verifying a gateway webhook; never trust amounts or payment status sent by a browser.

create or replace function public.admin_dashboard_summary()
returns jsonb language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_localfix_admin() then raise exception 'Admin access required'; end if;
  return jsonb_build_object(
    'profiles', (select count(*) from public.profiles),
    'providers', (select count(*) from public.provider_profiles),
    'bookings', (select count(*) from public.bookings),
    'completed_volume_ngn', coalesce((select sum(agreed_amount_ngn) from public.bookings where status='completed'),0),
    'commission_total_ngn', coalesce((select sum(commission_ngn) from public.payments where status='paid'),0)
  );
end $$;
revoke all on function public.admin_dashboard_summary() from public;
grant execute on function public.admin_dashboard_summary() to authenticated;

-- Automatically create a profile after auth signup; role is validated and defaults safely.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public
as $$
declare chosen_role text;
begin
  chosen_role := case when new.raw_user_meta_data->>'role' = 'provider' then 'provider' else 'customer' end;
  insert into public.profiles(id, full_name, role)
  values(new.id, coalesce(new.raw_user_meta_data->>'full_name',''), chosen_role)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created_localfix on auth.users;
create trigger on_auth_user_created_localfix after insert on auth.users
for each row execute procedure public.handle_new_user()
