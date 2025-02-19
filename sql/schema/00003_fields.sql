-- +goose Up
create table fields (
  id uuid primary key,
  created_at timestamp not null,
  updated_at timestamp not null,
  content text not null unique,
  site_id uuid not null,
  constraint fk_site
  foreign key (site_id)
    references sites(id)
    on delete cascade
);

-- +goose Down
drop table fields;
