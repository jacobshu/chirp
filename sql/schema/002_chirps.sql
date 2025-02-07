-- +goose Up
create table chirps (
  id uuid primary key,
  created_at timestamp not null,
  updated_at timestamp not null,
  body text not null unique,
  user_id uuid not null,
  constraint fk_user
  foreign key (user_id)
    references users(id)
    on delete cascade
);

-- +goose Down
drop table chirps;
