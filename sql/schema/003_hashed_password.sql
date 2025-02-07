-- +goose Up
alter table users 
add column hashed_password text default 'unset' not null;

-- +goose Down
alter table users
drop column hashed_password;
