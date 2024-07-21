alter table t_tokens
    drop constraint if exists t_tokens_username_fkey,
    add constraint  fk_users_tokens_delete
        foreign key (username) references t_users (login)
            on delete cascade;