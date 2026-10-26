# check-my-supabase (read-only checker)

**Only run this against a Supabase project you own or are authorized to test.**

`check-my-supabase.mjs` (v0.1.0) shows which tables in your own Supabase project a signed-out visitor (the anon role) can read.

- **Public key only.** It takes only your public anon or publishable key (`sb_publishable_...` or a legacy anon JWT). It refuses `sb_secret_` keys and any JWT whose role is not `anon`, such as a `service_role` key.
- **Read-only.** No writes, no RPC, no row data, no telemetry, no update checks, no redirects followed, no dependencies.
- **Requests.** At most 2 GET requests: your project's `robots.txt` and, only when you don't pass table names, the `/rest/v1/` OpenAPI schema. Then one HEAD request per table (a second HEAD only on a retry after HTTP 429/503, or without the row count if counting times out).
- **Limits.** It can miss problems and isn't an audit. Per the script: "Not tested: signed-in users, writes, views' security_invoker, RPC functions, Storage, GraphQL. This is not an audit or penetration test."

It asks you to type `yes, I own this project` before sending anything (or pass `--yes-i-own-this-project` for CI).

## Run

Requires Node.js 20 or newer. Usage, from the script's own help text (`--help`):

```text
Usage:
  check-my-supabase --from-env [path] --tables profiles,notes      (default target: your own local .env)
  check-my-supabase --url https://<ref>.supabase.co --key sb_publishable_... --tables profiles
  check-my-supabase --from-env --from-code ./src
```

From this repo, call the file with Node, for example:

```bash
node checker/check-my-supabase.mjs --from-env .env --tables profiles,notes
```

Run `node checker/check-my-supabase.mjs --help` for all options.

Exit codes (from the help text): 0 nothing returns rows, 2 at least one table returns rows, 1 usage or network error, 3 a secret key or service_role JWT was found in your code (`--from-code`).

Provided as is (MIT). Results may be incomplete or wrong.
