# frontend-epl (Email/Password login to Cognito from frontend)

- Login with email & password (SRP) using `amazon-cognito-identity-js`
- Extract `custom:tenant_id` from ID token payload
- Call Django backend with headers:
    - `Authorization: Bearer <access_token>`
    - `X-Tenant-Id: <tenant_id>`

## Run
```bash
pnpm i   # or npm i / yarn
cp .env.example .env.local
pnpm dev
```
