ALTER TABLE tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE refresh_tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';

DELETE FROM refresh_tokens WHERE scope = '';
DELETE FROM tokens WHERE scope = '';
