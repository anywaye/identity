-- +goose Up
-- +goose StatementBegin
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'identity_app') then
    grant usage on schema anywaye to identity_app;
    grant execute on all functions in schema anywaye to identity_app;
  end if;
end
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'identity_app') then
    revoke execute on all functions in schema anywaye from identity_app;
    revoke usage on schema anywaye from identity_app;
  end if;
end
$$;
-- +goose StatementEnd
