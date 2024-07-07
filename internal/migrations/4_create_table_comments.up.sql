create table if not exists t_comments
(
    id         bigserial primary key not null,
    created_at timestamp             not null default now(),
    created_by varchar(255)          not null references t_users (login),
    comment    text                  not null
);

create table if not exists t_blogs_comments
(
    blog_id    bigint not null references t_blogs (id),
    comment_id bigint not null references t_comments (id)
)