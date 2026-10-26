# Supabase security checklist

Live version: https://patchandship.com/supabase-rls-checklist

Free passive homepage check: [patchandship.com/check](https://patchandship.com/check.html?utm_source=github&utm_medium=readme&utm_campaign=checklist). It reads your homepage, up to 10 of its JS files and its headers, with no database queries.

## Supabase RLS checklist for Lovable, Bolt and Cursor apps (free, CC BY 4.0)

By the PatchAndShip team. Last verified on the live page: 2026-10-14.

PatchAndShip's free Supabase RLS checklist covers seven checks for apps built with Lovable, Bolt or Cursor: Row Level Security on every table in the public schema, one owner policy per operation, views that respect RLS, a signed-out test, no secret keys in the frontend, non-public storage for files that belong to one user, and grants for new tables only where needed.

**Copy this: the checklist in 10 lines**

1. Turn on Row Level Security for every table in the `public` schema.
2. Add policies in the same migration that turns RLS on.
3. Write one policy per operation: select, insert, update, delete.
4. Limit each policy to `authenticated` and compare the owner column to `(select auth.uid())`.
5. Never ship `using (true)` on data that belongs to one user.
6. On Postgres 15 and above, create views with `security_invoker = true`. On older versions, revoke view access from `anon` and `authenticated`, or keep views in an unexposed schema.
7. Sign out and request every table with only the public key: non-public tables return `[]` or an error.
8. Keep `service_role` and `sb_secret_` keys out of the frontend, the built bundle and git history.
9. Make buckets that hold per-user files non-public, with policies on `storage.objects`.
10. For new tables, grant only what each role needs and never `GRANT ALL` to anon.

Run every check against an app you own. The SQL below uses an `orders` table with a `user_id` owner column as the example. Change the names to match your tables.

### 1. Does every table in `public` have RLS turned on?

**Check.** In the Supabase SQL editor:

```sql
select c.relname as table_name
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and not c.relrowsecurity;
```

Any table listed has RLS off. You can also open **Advisors, then Security Advisor**, in the dashboard. It flags RLS disabled on a public table as an error (lint 0013): "Anyone with your project URL can read, edit, and delete all data in this table because Row‑Level Security is not enabled." ([Supabase: Database Advisors](https://supabase.com/docs/guides/database/database-advisors))

**Fix.** Enable RLS and add policies **in the same change**:

```sql
alter table public.your_table enable row level security;
```

Then add the policies from step 2 in that same migration. Supabase: "Once RLS is enabled, no data is accessible through the API when using a publishable key, until you create policies." ([Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security))

### 2. Is each policy written per operation and limited to the owner?

Supabase's Security Advisor flags always‑true policy conditions such as `using (true)` as a permissive RLS policy (lint 0024, a warning) ([Supabase: Database Advisors](https://supabase.com/docs/guides/database/database-advisors)). Supabase also notes that when a request has no signed‑in user (no access token, or the session has expired), `auth.uid()` returns null ([Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)).

**Our guidance:** a policy of `using (true)` lets everyone in, and a check of `auth.uid() is not null` on its own lets any signed‑in user reach every other user's rows. Compare `auth.uid()` to the row's owner column instead, as below.

**Fix.** One policy per operation, limited to the `authenticated` role, comparing the row's owner column to the caller:

```sql
create policy "orders_select_own" on public.orders
  for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "orders_insert_own" on public.orders
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "orders_update_own" on public.orders
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "orders_delete_own" on public.orders
  for delete to authenticated
  using ((select auth.uid()) = user_id);
```

The update policy uses both clauses. In Supabase's explanation, `using` decides which existing rows can be updated, and `with check` decides what the resulting row may look like, which stops a user from reassigning `user_id` to someone else. If `with check` is left out, `using` is applied to both ([Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security); [PostgreSQL: CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html)). **Our guidance:** write both, so the rule for the new row is explicit.

The policies wrap the call as `(select auth.uid())`. Supabase says this makes Postgres run an initPlan that caches the result per statement instead of calling the function on each row, which improves RLS performance. It only works when the result doesn't depend on row data ([Supabase: RLS performance and best practices](https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv)).

**Check.** The two‑account test: sign in as user A, copy the ID of a record that belongs to user B, and try to load, edit, and delete it through the app or a direct API call. Every attempt should fail.

### 3. Can a view get around RLS?

Supabase's Security Advisor flags a security definer view as an error (lint 0010) ([Supabase: Database Advisors](https://supabase.com/docs/guides/database/database-advisors)). Views bypass RLS by default because they run with the view owner's permissions, and in Supabase views are usually created by the `postgres` user ([Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security); [PostgreSQL: CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html)).

**Fix.** On Postgres 15 and above, create views with `security_invoker = true`, so the view follows the caller's RLS policies:

```sql
create view public.public_profiles
with (security_invoker = true) as
select id, display_name, avatar_url from public.profiles;
```

On older Postgres versions, revoke access to the view from `anon` and `authenticated`, or put it in an unexposed schema ([Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security)).

### 4. What does a signed‑out visitor see?

**Check.** Open your live app, open DevTools, then the Network tab, and find a request to `https://<project>.supabase.co/rest/v1/...`. Copy the `apikey` header value. Then, from a terminal:

```bash
curl "https://<project>.supabase.co/rest/v1/<table>?select=*&limit=5" \
  -H "apikey: <public-key>"
```

Run it for every table. Non-public tables should return `[]` or a permission error. If one returns rows, anyone on the internet can do exactly what you just did. Run this only against an app you own.

### 5. Is any secret key in your frontend or repo history?

Supabase: "A secret key bypasses every Row Level Security policy you have. Never put one in a browser, a shipped application, or source control." Publishable (anon) keys are designed to be public ([Supabase: API keys](https://supabase.com/docs/guides/api/api-keys)).

**Check.**

* Search the **built** bundle: `npm run build`, then `grep -rE "sk_live_|sb_secret_|service_role|c2VydmljZV9yb2xl|NlcnZpY2Vfcm9s|zZXJ2aWNlX3Jv" dist/`. The last three patterns catch a legacy `service_role` key: it's a JWT (starts with `eyJ`), so the word "service\_role" only appears base64-encoded inside it.
* History: `git log -p --all | grep -E "sk_live_|sb_secret_|service_role|c2VydmljZV9yb2xl|NlcnZpY2Vfcm9s|zZXJ2aWNlX3Jv"`.

If a secret was ever committed, GitHub says to revoke or rotate it first. Removing it from git history means rewriting history, and the old commits may still be reachable elsewhere afterwards, for example in clones, forks, cached views and pull requests ([GitHub: Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)).

**Fix, in order (our guidance):**

1. Move the code that needs the secret to a server, such as a Supabase Edge Function or an API route.
2. Create a new key.
3. Deploy the new key everywhere it's used.
4. Revoke the old key.

Revoke last, or production breaks while you're still deploying.

### 6. Do your storage buckets match what's in them?

Supabase Storage buckets are not public by default. For a public bucket, "anyone who possesses the asset URL can readily access the file". Supabase's examples of public content are profile pictures, public media and blog content ([Supabase: Storage Buckets](https://supabase.com/docs/guides/storage/buckets/fundamentals)).

**Check.** In the dashboard, open Storage and look at which buckets are marked Public. Check whether a public bucket holds anything that belongs to one user, such as IDs, invoices, uploads or exports.

**Fix.** Set buckets that hold per-user files to non-public and add policies on `storage.objects`.

### 7. Are new tables granted only what they need?

From **October 30, 2026**, Supabase will apply this change to existing projects: new tables you create in the `public` schema will need an explicit grant before the Data API (the auto‑generated REST and GraphQL layer) can see them. Existing tables keep their current grants and stay reachable. New projects have had this behavior by default since the May 30, 2026 rollout. Until October 30, the Security Advisor flags affected tables and shows the SQL to fix them ([Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)).

In Supabase's words: "If the grant is missing, Postgres rejects the query before RLS comes into play." A table with no grant returns error `42501` "permission denied for table" even if your policies are perfect. The risk is the quick fix: an AI tool suggesting `grant all on table ... to anon`. Grants control whether a role can reach a table, and RLS controls which rows it can access ([Supabase: Securing your API](https://supabase.com/docs/guides/api/securing-your-api)). Once the grant exists, RLS is the only thing left guarding the table. So a grant on a table with RLS off makes it fully public.

**Fix (our guidance):** grant only what each role needs, keep RLS on with policies, and never `GRANT ALL` to anon. Supabase's own fix treats the grant, enabling RLS, and the policies as one unit, so put them in one migration:

```sql
begin;
alter table public.orders enable row level security;
revoke all on table public.orders from anon, authenticated;
grant select, insert, update, delete on table public.orders to authenticated;

create policy "orders_select_own" on public.orders
  for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "orders_insert_own" on public.orders
  for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "orders_update_own" on public.orders
  for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "orders_delete_own" on public.orders
  for delete to authenticated
  using ((select auth.uid()) = user_id);
commit;
```

These are the four policies from step 2. If you already created them, leave them out of this block. Grant `anon` access only for data signed‑out visitors truly need, and usually only `select`.

More detail: [Supabase error 42501 "permission denied for table": what it means and the safe fix](https://patchandship.com/blog/supabase-42501-permission-denied-oct-30).

### How can I reuse this checklist?

#### Text: CC BY 4.0

The text of this checklist is licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/). You can copy, adapt and republish it, including commercially, if you give credit.

#### SQL and commands: MIT

The SQL snippets and commands are licensed under the [MIT License](https://opensource.org/license/mit). Creative Commons says: "We recommend against using Creative Commons licenses for software" ([CC FAQ](https://creativecommons.org/faq/)).

Attribution line for the text:

**Supabase RLS checklist by PatchAndShip, https://patchandship.com/supabase-rls-checklist, CC BY 4.0**

Full MIT license for the SQL snippets:

```text
MIT License

Copyright (c) 2026 PatchAndShip

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```

### How do I cite it?

Suggested citation:

Supabase RLS checklist by PatchAndShip, https://patchandship.com/supabase-rls-checklist, CC BY 4.0. Last verified 2026-10-14.

### Where do these facts come from?

1. [Supabase Docs: Database Advisors](https://supabase.com/docs/guides/database/database-advisors). Lint 0013 (RLS disabled on a public table), 0024 (permissive RLS policy), 0010 (security definer view).
2. [Supabase Docs: Securing your API](https://supabase.com/docs/guides/api/securing-your-api). Grants and RLS.
3. [Supabase Docs: API keys](https://supabase.com/docs/guides/api/api-keys). Secret and publishable keys.
4. [Supabase Docs: Storage Buckets](https://supabase.com/docs/guides/storage/buckets/fundamentals). Non-public and public buckets.
5. [Supabase changelog: Breaking Change: Tables not exposed to Data and GraphQL API automatically](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically). Published 28 Apr 2026. The October 30, 2026 grants change.
6. [Supabase Docs: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security). No data until policies exist, `auth.uid()` when signed out, update policies, views.
7. [Supabase Troubleshooting: RLS performance and best practices](https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv). Wrapping `auth.uid()` in a select.
8. [PostgreSQL Docs: CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html) and [CREATE VIEW](https://www.postgresql.org/docs/current/sql-createview.html). Update policies and view permissions.
9. [GitHub Docs: Removing sensitive data from a repository](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository). Secrets in git history.

All sources checked on 2026-10-14. Instructions marked as our guidance are ours, not Supabase's.

Want it done for you? [patchandship.com](https://patchandship.com/)

## Read-only checker

[`checker/`](checker/) holds `check-my-supabase.mjs`, a read-only script that shows which tables in your own Supabase project a signed-out visitor (the anon role) can read. See [checker/README.md](checker/README.md) before you run it.

## Changelog

- 2026-10-26: first version, mirrored from patchandship.com/supabase-rls-checklist.

From Oct 30, 2026, Supabase plans to stop auto-granting new public-schema tables on existing projects. Once the change reaches your project, new tables need an explicit GRANT. Existing tables keep their grants and RLS is unchanged. Source: https://supabase.com/changelog/45329

Not affiliated with Supabase, Lovable, Bolt, Replit or Cursor.
