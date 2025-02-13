-- +goose Up
create table refresh_tokens (
  token text primary key,
  created_at timestamp not null,
  updated_at timestamp not null,
  user_id uuid not null,
  constraint fk_user 
    foreign key (user_id) references users(id) on delete cascade,
  expires_at timestamp not null,
  revoked_at timestamp default null
);

-- +goose Down
drop table refresh_tokens;
