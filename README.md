# Ticket System in Golang

Small backend service for the backend intern assignment.

## Local Run

```bash
go run .
```

## Docker Run

```bash
docker build -t ticket-system .
docker run -p 8080:8080 ticket-system
```

## Deploy on Vercel

This project is already structured as a Go server that Vercel can detect from the root `main.go` file.

### Vercel Dashboard

1. Push the repository to GitHub.
2. Create a new project in Vercel and import that GitHub repo.
3. Keep the framework preset as `Go`.
4. Add `JWT_SECRET` in Environment Variables if you want a custom secret.
5. Deploy.

### Vercel CLI

```bash
npm i -g vercel
vercel login
vercel link
vercel env add JWT_SECRET production
vercel deploy --prod
```

`PORT` is provided by Vercel automatically at runtime, so the server already listens on the correct port.

Vercel will use the `PORT` environment variable at runtime, and the public `/health` endpoint will be available after deployment.

## Public Endpoints

- `GET /health`
- `POST /auth/register`
- `POST /auth/login`
- `POST /tickets`
- `GET /tickets`
- `GET /tickets/{id}`
- `PATCH /tickets/{id}/status`

## Ticket List Response

`GET /tickets` returns a JSON array of the logged-in user's tickets.

## Environment

Use `.env.example` as a template.

- `PORT` defaults to `8080`
- `JWT_SECRET` defaults to `dev-secret` if not set

## Notes

- Storage is in memory.
- Passwords are hashed before storage.
- JWT auth is required for all ticket routes.
