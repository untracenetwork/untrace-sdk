# Next.js example

Copy `app/` into a Next.js 14+ App Router project, then:

```bash
npm i @untracenetwork/next @untracenetwork/react
# .env.local (server only, never NEXT_PUBLIC_)
UNTRACE_CLIENT_ID=utc_...
UNTRACE_CLIENT_SECRET=untrace_sk_v1_...
```

- `app/api/untrace/route.ts`: the route. Encryption, decryption and the secret stay here.
- `app/page.tsx`: a client page that lists and uploads files through the route, into the first folder the key can write to.
