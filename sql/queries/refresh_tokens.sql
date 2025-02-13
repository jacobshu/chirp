-- name: CreateRefreshToken :one
insert into refresh_tokens (token, created_at, updated_at, user_id, expires_at)
values(
  $1,
  now(),
  now(),
  $2,
  $3
)
returning *;

-- name: GetRefreshToken :one
select * from refresh_tokens
where token = $1;

-- name: RevokeRefreshToken :exec
update refresh_tokens
set revoked_at = now()
where token = $1;
