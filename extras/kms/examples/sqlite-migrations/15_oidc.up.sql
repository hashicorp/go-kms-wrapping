-- Copyright (c) HashiCorp, Inc.
-- SPDX-License-Identifier: MPL-2.0

create table oidc (
    private_id text not null primary key,
    client_id text not null,
    client_secret blob not null,
    key_version_id text not null
        references kms_data_key_version(private_id)
        on delete restrict -- keep a data key from being deleted while it's in use
        on update cascade,
    create_time timestamp not null default current_timestamp
);
