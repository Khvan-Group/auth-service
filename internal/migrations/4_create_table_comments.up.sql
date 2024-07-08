create table if not exists t_comments
(
    id         bigserial primary key not null,
    created_at timestamp             not null default now(),
    created_by varchar(255)          not null references t_users (login),
    blog_id    bigint                not null references t_blogs (id),
    comment    text                  not null
);

create unique index udx_blog_comment on t_comments (blog_id, created_by);