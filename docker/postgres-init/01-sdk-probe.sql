-- Test-only table: dynamic credentials from the `sdk-readonly` role can SELECT it.
CREATE TABLE IF NOT EXISTS public.sdk_probe (id integer PRIMARY KEY, label text NOT NULL);
INSERT INTO public.sdk_probe (id, label) VALUES (1, 'grow-sdk') ON CONFLICT DO NOTHING;
