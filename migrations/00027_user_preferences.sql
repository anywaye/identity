-- 00027_user_preferences.sql — `users.preferences`: the profile's own settings.
--
-- ONE JSONB COLUMN, ONE KEY TODAY. The reference (Jumpstart Pro) stores
-- preferences in a single jsonb column on users and puts exactly one key in it:
-- the theme. The closed set is absent (the system theme), "light" and "dark" —
-- nothing else is a theme, and this migration does not invent a second key.
--
-- A jsonb DOCUMENT rather than a `theme` text column, because the reference's
-- shape is a document: the next key this profile wants is one Go change and one
-- UPDATE, not one migration. A text column would be a second schema for the same
-- fact, and the day a second key landed the column would have to be converted
-- to jsonb anyway — the expand/contract the prod section of migrations/README.md
-- describes, paid in advance rather than in an incident.
--
-- NOT NULL DEFAULT '{}'::jsonb, which is the opposite of 00023's argument for a
-- nullable display_name and deliberately so. A display name is a VALUE, where
-- "nobody has decided" is a state worth naming; a preferences document is a
-- CONTAINER, and an empty container is the natural "nothing in it" — a NULL
-- document would be a second representation of the same fact, and the scan
-- target would have to be a pointer to a pointer to tell them apart. The
-- default is also what makes every user row that exists today read as "no
-- preferences" rather than as "no column": the theme key's ABSENCE inside the
-- document is what means the system theme, which is the reference's own
-- `theme.blank?` (User::Theme), and a row that has never had a preference set
-- and a row whose theme was cleared are the same row.
--
-- NO INDEX, for the reason 00023 gives for display_name: nothing looks a user
-- up by a preference. Every read of this column already has the user row in hand
-- — it came from the session's user lookup — so an index would be maintained on
-- every write to `users` and read by nothing.
--
-- +goose Up

ALTER TABLE users
    ADD COLUMN preferences jsonb NOT NULL DEFAULT '{}'::jsonb;

-- +goose Down

-- The column goes with it, and the rollback is a rollback of the ENFORCEMENT
-- rather than of the data, on the same terms as 00023: the handler that writes
-- the column is deployed after this migration and the one that stops reading it
-- is deployed before it. A preference is re-chosen in one request, and the
-- theme key is one of two values or absent — no row carries a value that
-- outlives the column.
ALTER TABLE users
    DROP COLUMN preferences;
