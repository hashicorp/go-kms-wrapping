create table scope (
    private_id text not null primary key,
    create_time timestamp not null default current_timestamp
);

drop table kms_root_key;

create table kms_root_key (
    private_id text not null primary key,
    scope_id text not null unique
        references scope(private_id)
        on delete cascade
        on update cascade
        check(
            scope_id > 10 or scope_id = 'global'
        ),
    create_time timestamp not null default current_timestamp
);
