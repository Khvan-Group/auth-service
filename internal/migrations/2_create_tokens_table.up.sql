create table if not exists t_tokens (
    token varchar not null primary key,
    username varchar(255) not null references t_users(login),
    expiration_deadline timestamp not null
);

create unique index if not exists udx_tokens_user_token on t_tokens(token, username);