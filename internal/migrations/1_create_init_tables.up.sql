create type role_code as enum ('USER', 'BLOGGER', 'MODERATOR', 'ADMIN');

create table if not exists t_roles
(
    code role_code primary key not null,
    name varchar(255)             not null
);

insert into t_roles
values ('USER', 'Пользователь'),
       ('BLOGGER', 'Блогер'),
       ('MODERATOR', 'Модератор'),
       ('ADMIN', 'Администратор');

create table if not exists t_users
(
    login       varchar(255) primary key not null,
    created_at  timestamp                not null                           default now(),
    created_by  varchar(255)             not null references t_users (login),
    updated_at  timestamp,
    updated_by  varchar(255) references t_users (login),
    password    varchar(255)             not null,
    email       varchar(255)             not null unique,
    first_name  varchar(255)             not null,
    middle_name varchar(255),
    last_name   varchar(255)             not null,
    birthdate   date                     not null,
    role        role_code             not null references t_roles (code) default 'USER',
    deleted_at  timestamp,
    deleted_by  varchar(255) references t_users (login),
    is_deleted  boolean                  not null                           default false
);