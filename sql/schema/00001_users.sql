-- +goose Up
create table users (
  id uuid primary key,
  created_at timestamp not null,
  updated_at timestamp not null,
  email text not null unique,
  hashed_password text default 'unset' not null
);

-- +goose Down
drop table users;
