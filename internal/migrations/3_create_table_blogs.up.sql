create type blog_status as enum ('DRAFT', 'IN_REVIEW', 'ACTIVATED', 'REJECTED');
create type blog_category as enum ('IT', 'NEWS', 'MANAGEMENT', 'BUSINESS', 'GAMES', 'TRAVEL');

create table if not exists t_blogs
(
    id         bigserial primary key not null,
    created_at timestamp             not null default now(),
    created_by varchar(255)          not null references t_users (login),
    updated_at timestamp,
    updated_by varchar(255) references t_users (login),
    title      varchar(255)          not null,
    content    text                  not null,
    status     blog_status           not null default 'DRAFT',
    category   blog_category         not null,
    likes      int                   not null default 0,
    favorites  int                   not null default 0,
    watches    int                   not null default 0,
    deleted_at timestamp,
    deleted_by varchar(255) references t_users (login),
    is_deleted boolean               not null default false
)