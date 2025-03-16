--
-- PostgreSQL database dump
--

-- Dumped from database version 16.6
-- Dumped by pg_dump version 16.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: mailserver; Type: DATABASE; Schema: -; Owner: postgres
--

CREATE DATABASE mailserver WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'en_US.UTF-8';


ALTER DATABASE mailserver OWNER TO postgres;

\connect mailserver

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: pg_database_owner
--

CREATE SCHEMA public;


ALTER SCHEMA public OWNER TO pg_database_owner;

--
-- Name: SCHEMA public; Type: COMMENT; Schema: -; Owner: pg_database_owner
--

COMMENT ON SCHEMA public IS 'standard public schema';


--
-- Name: change_domain_accepts_email(bigint, boolean, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.change_domain_accepts_email(domain_id bigint, accepts_email boolean, self_user_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT change_domain_accepts_email.domain_id as id FROM flattened_web_domain_permissions perms
    WHERE
        perms.user_id = change_domain_accepts_email.self_user_id AND change_domain_accepts_email.domain_id = perms.domain_id AND
        (perms.is_owner OR perms.admin OR (perms.modify_domain AND perms.view_domain))
) UPDATE domains SET accepts_email = change_domain_accepts_email.accepts_email FROM valid_values WHERE domains.id = valid_values.id AND domains.deleted = false RETURNING domains.id
$$;


ALTER FUNCTION public.change_domain_accepts_email(domain_id bigint, accepts_email boolean, self_user_id bigint) OWNER TO postgres;

--
-- Name: change_domain_name(bigint, text, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.change_domain_name(domain_id bigint, name text, self_user_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT change_domain_name.domain_id as id FROM flattened_web_domain_permissions perms
    WHERE
        perms.user_id = change_domain_name.self_user_id AND change_domain_name.domain_id = perms.domain_id AND
        perms.is_owner OR perms.admin OR (perms.modify_domain AND perms.view_domain)
) UPDATE domains SET name = change_domain_name.name FROM valid_values WHERE domains.id = valid_values.id AND domains.deleted = false RETURNING domains.id
$$;


ALTER FUNCTION public.change_domain_name(domain_id bigint, name text, self_user_id bigint) OWNER TO postgres;

--
-- Name: change_domain_owner(bigint, bigint, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.change_domain_owner(domain_id bigint, new_owner_id bigint, self_user_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT change_domain_owner.domain_id as id FROM users
           JOIN flattened_web_domain_permissions self_perms ON self_perms.user_id = change_domain_owner.self_user_id AND change_domain_owner.domain_id = self_perms.domain_id
    WHERE users.id = change_domain_owner.new_owner_id AND users.deleted = false AND
          (self_perms.is_owner OR self_perms.super_owner)
) UPDATE domains SET domain_owner = change_domain_owner.new_owner_id FROM valid_values 
    WHERE domains.id = change_domain_owner.domain_id AND domains.deleted = false
    RETURNING domains.id
$$;


ALTER FUNCTION public.change_domain_owner(domain_id bigint, new_owner_id bigint, self_user_id bigint) OWNER TO postgres;

--
-- Name: delete_alias(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.delete_alias(alias_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT alias_ids.id as id FROM unnest(delete_alias.alias_ids) as alias_ids(id)
        JOIN virtual_aliases ON virtual_aliases.id = alias_ids.id
        JOIN users ON users.id = virtual_aliases.destination
        JOIN flattened_web_domain_permissions source_perms ON source_perms.user_id = delete_alias.self_id AND users.domain_id = source_perms.domain_id
        JOIN flattened_web_domain_permissions destination_perms ON destination_perms.user_id = delete_alias.self_id AND destination_perms.domain_id = virtual_aliases.domain_id
    WHERE (source_perms.is_owner OR source_perms.admin OR (source_perms.delete_alias AND source_perms.list_alias))
        OR (destination_perms.is_owner OR destination_perms.admin OR (destination_perms.delete_alias AND destination_perms.list_alias))
) DELETE FROM virtual_aliases USING valid_values WHERE virtual_aliases.id = valid_values.id RETURNING virtual_aliases.id
$$;


ALTER FUNCTION public.delete_alias(alias_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: delete_subdomain(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.delete_subdomain(domain_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT domain_ids.id as id FROM unnest(delete_subdomain.domain_ids) as domain_ids(id)
          JOIN domains ON domains.id = domain_ids.id
          JOIN flattened_web_domain_permissions perms ON perms.user_id = delete_subdomain.self_id AND perms.domain_id = domains.super
          JOIN flattened_web_domain_permissions sub_perms ON sub_perms.user_id = delete_subdomain.self_id AND sub_perms.domain_id = domains.id
    WHERE (perms.is_owner OR perms.admin OR (perms.delete_disabled AND perms.list_deleted AND (sub_perms.view_domain OR sub_perms.is_owner OR sub_perms.admin) ))
      AND domains.deleted = true
) DELETE FROM domains USING valid_values WHERE domains.id = valid_values.id returning domains.id;
$$;


ALTER FUNCTION public.delete_subdomain(domain_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: delete_users(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.delete_users(user_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT user_ids.id as id FROM unnest(delete_users.user_ids) as user_ids(id)
                                      JOIN users ON users.id = user_ids.id
                                      JOIN flattened_web_domain_permissions perms ON perms.user_id = delete_users.self_id AND users.domain_id = perms.domain_id
    WHERE (perms.is_owner OR perms.admin OR (perms.delete_disabled AND perms.list_deleted AND perms.list_accounts)) AND users.deleted = true
) DELETE FROM users USING valid_values WHERE users.id = valid_values.id returning users.id
$$;


ALTER FUNCTION public.delete_users(user_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: disable_subdomain(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.disable_subdomain(domain_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT domain_ids.id as id FROM unnest(disable_subdomain.domain_ids) as domain_ids(id)
          JOIN domains ON domains.id = domain_ids.id
          JOIN flattened_web_domain_permissions perms ON perms.user_id = disable_subdomain.self_id AND perms.domain_id = domains.super
          JOIN flattened_web_domain_permissions sub_perms ON sub_perms.user_id = disable_subdomain.self_id AND sub_perms.domain_id = domains.id
    WHERE (perms.is_owner OR perms.admin OR (perms.delete_subdomain AND sub_perms.view_domain))
) UPDATE domains SET deleted = true FROM valid_values WHERE domains.id = valid_values.id returning domains.id;
$$;


ALTER FUNCTION public.disable_subdomain(domain_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: disable_users(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.disable_users(user_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT user_ids.id as id FROM unnest(disable_users.user_ids) as user_ids(id)
                                      JOIN users ON users.id = user_ids.id
                                      JOIN flattened_web_domain_permissions perms ON perms.user_id = disable_users.self_id AND users.domain_id = perms.domain_id
    WHERE (perms.is_owner OR perms.admin OR (perms.delete_accounts AND perms.list_accounts))
) UPDATE users SET deleted = true FROM valid_values WHERE users.id = valid_values.id returning users.id;
$$;


ALTER FUNCTION public.disable_users(user_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: insert_new_account(bigint, text, text, text, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_new_account(domain_id bigint, email text, password_hash text, dovecot_type text, self_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
    WITH new_account AS (
        SELECT insert_new_account.domain_id, insert_new_account.email, insert_new_account.password_hash as password, insert_new_account.dovecot_type
        FROM flattened_web_domain_permissions perm
        WHERE perm.domain_id = insert_new_account.domain_id AND perm.user_id = insert_new_account.self_id
            AND (perm.is_owner OR perm.admin OR (perm.create_accounts AND perm.list_accounts))
    ) INSERT INTO users (domain_id, email, password, dovecot_type) SELECT domain_id, email, password, dovecot_type FROM new_account RETURNING id
$$;


ALTER FUNCTION public.insert_new_account(domain_id bigint, email text, password_hash text, dovecot_type text, self_id bigint) OWNER TO postgres;

--
-- Name: insert_new_alias(bigint, text, bigint, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_new_alias(domain_id bigint, email text, target_user_id bigint, self_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT insert_new_alias.email as src, insert_new_alias.target_user_id as id FROM virtual_users target
           JOIN flattened_web_domain_permissions target_perms ON target_perms.domain_id = target.domain_id AND target_perms.user_id = insert_new_alias.self_id
           JOIN flattened_web_domain_permissions self_perms ON self_perms.domain_id = insert_new_alias.domain_id AND self_perms.user_id = insert_new_alias.self_id
    WHERE target.id = insert_new_alias.target_user_id AND
          (target_perms.is_owner OR target_perms.admin OR target_perms.list_accounts) AND
          (self_perms.is_owner OR self_perms.admin OR self_perms.create_alias)
) INSERT INTO virtual_aliases (source, domain_id, destination) SELECT src, insert_new_alias.domain_id, id FROM valid_values RETURNING id
$$;


ALTER FUNCTION public.insert_new_alias(domain_id bigint, email text, target_user_id bigint, self_id bigint) OWNER TO postgres;

--
-- Name: insert_subdomain(bigint, text, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.insert_subdomain(domain_id bigint, subdomain text, self_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT insert_subdomain.domain_id as id FROM flattened_web_domain_permissions self_perms
    WHERE self_perms.domain_id = insert_subdomain.domain_id AND self_perms.user_id = insert_subdomain.self_id AND
          (self_perms.is_owner OR self_perms.admin OR (self_perms.create_subdomain AND self_perms.list_subdomain))
) INSERT INTO domains (name, super, domain_owner) SELECT insert_subdomain.subdomain, id, insert_subdomain.self_id FROM valid_values RETURNING id
$$;


ALTER FUNCTION public.insert_subdomain(domain_id bigint, subdomain text, self_id bigint) OWNER TO postgres;

--
-- Name: mark_deleted(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.mark_deleted() RETURNS trigger
    LANGUAGE plpgsql LEAKPROOF
    AS $_$
BEGIN
    if tg_nargs != 3 then
        RAISE EXCEPTION 'Expected 3 arguments, got %', tg_nargs;
    end if;
    EXECUTE 'UPDATE ' || TG_ARGV[0] || ' SET ' || TG_ARGV[1] || ' = true WHERE ' || TG_ARGV[2] || ' = $1.' || TG_ARGV[2]
        USING OLD;
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN OLD;
END
$_$;


ALTER FUNCTION public.mark_deleted() OWNER TO postgres;

--
-- Name: recover_subdomain(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.recover_subdomain(domain_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT domain_ids.id as id FROM unnest(recover_subdomain.domain_ids) as domain_ids(id)
          JOIN domains ON domains.id = domain_ids.id
          JOIN flattened_web_domain_permissions perms ON perms.user_id = recover_subdomain.self_id AND perms.domain_id = domains.super
          JOIN flattened_web_domain_permissions sub_perms ON sub_perms.user_id = recover_subdomain.self_id AND sub_perms.domain_id = domains.id
    WHERE (perms.is_owner OR perms.admin OR (perms.undelete AND perms.list_deleted AND (sub_perms.view_domain OR sub_perms.is_owner OR sub_perms.admin) ))
      AND domains.deleted = TRUE
) UPDATE domains SET deleted = false FROM valid_values WHERE domains.id = valid_values.id returning domains.id;
$$;


ALTER FUNCTION public.recover_subdomain(domain_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: recover_users(bigint[], bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.recover_users(user_ids bigint[], self_id bigint) RETURNS SETOF bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT user_ids.id as id FROM unnest(recover_users.user_ids) as user_ids(id)
      JOIN users ON users.id = user_ids.id
      JOIN flattened_web_domain_permissions perms ON perms.user_id = recover_users.self_id AND users.domain_id = perms.domain_id
    WHERE (perms.is_owner OR perms.admin OR (perms.undelete AND perms.list_deleted AND perms.list_accounts))
        AND users.deleted = true
) UPDATE users SET deleted = false FROM valid_values WHERE users.id = valid_values.id returning users.id;
$$;


ALTER FUNCTION public.recover_users(user_ids bigint[], self_id bigint) OWNER TO postgres;

--
-- Name: set_user_email(bigint, text, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.set_user_email(user_id bigint, email text, self_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT set_user_email.user_id FROM users
          JOIN flattened_web_domain_permissions perms ON perms.user_id = set_user_email.self_id AND
             perms.domain_id = users.domain_id
    WHERE users.id = set_user_email.user_id AND perms.is_owner OR perms.admin OR (perms.list_accounts AND perms.modify_accounts)
) UPDATE users SET email = set_user_email.email FROM valid_values WHERE users.id = valid_values.user_id returning users.id;
$$;


ALTER FUNCTION public.set_user_email(user_id bigint, email text, self_id bigint) OWNER TO postgres;

--
-- Name: set_user_password(bigint, text, text, bigint); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.set_user_password(user_id bigint, password text, dovecot_type text, self_id bigint) RETURNS bigint
    LANGUAGE sql LEAKPROOF
    AS $$
WITH valid_values AS (
    SELECT set_user_password.user_id FROM users
          JOIN flattened_web_domain_permissions perms ON perms.user_id = set_user_password.self_id AND
             perms.domain_id = users.domain_id
    WHERE users.id = set_user_password.user_id AND
          (perms.is_owner OR perms.admin OR (perms.list_accounts AND perms.modify_accounts))
) UPDATE users SET password = set_user_password.password, dovecot_type = set_user_password.dovecot_type FROM valid_values WHERE users.id = valid_values.user_id returning users.id;
$$;


ALTER FUNCTION public.set_user_password(user_id bigint, password text, dovecot_type text, self_id bigint) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: domains; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.domains (
    id bigint NOT NULL,
    name text NOT NULL,
    super bigint DEFAULT 0 NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    domain_owner bigint DEFAULT 1,
    accepts_email boolean DEFAULT true NOT NULL
);


ALTER TABLE public.domains OWNER TO postgres;

--
-- Name: domains_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.domains ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.domains_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: flattened_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.flattened_domains AS
 WITH RECURSIVE test AS (
         SELECT domains.id,
            (0)::bigint AS level,
                CASE
                    WHEN (domains.name = '.'::text) THEN 'root'::text
                    ELSE domains.name
                END AS name,
            domains.deleted,
            ARRAY[]::bigint[] AS super,
            ARRAY[domains.domain_owner] AS domain_owner,
            domains.accepts_email
           FROM public.domains
          WHERE (domains.id = domains.super)
        UNION ALL
         SELECT domains.id,
            (test_1.level + 1),
                CASE
                    WHEN (cardinality(test_1.super) = 0) THEN domains.name
                    ELSE concat(domains.name, '.', test_1.name)
                END AS concat,
            (test_1.deleted OR domains.deleted),
            array_prepend(domains.super, test_1.super) AS array_prepend,
            array_prepend(domains.domain_owner, test_1.domain_owner) AS array_prepend,
            domains.accepts_email
           FROM (test test_1
             JOIN public.domains ON (((domains.super = test_1.id) AND (domains.id <> test_1.id))))
        )
 SELECT id,
    name,
    deleted,
    super,
    domain_owner,
    accepts_email,
    level
   FROM test;


ALTER VIEW public.flattened_domains OWNER TO postgres;

--
-- Name: system_config; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.system_config AS
 SELECT uid,
    gid
   FROM ( VALUES ('docker'::text,'docker'::text)) x(uid, gid);


ALTER VIEW public.system_config OWNER TO postgres;

--
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    id bigint NOT NULL,
    domain_id bigint NOT NULL,
    password text NOT NULL,
    email text NOT NULL,
    dovecot_type text DEFAULT ''::text NOT NULL,
    deleted boolean DEFAULT false NOT NULL,
    quota_limit_bytes bigint DEFAULT (((1024)::double precision ^ (3)::double precision) * (10)::double precision) NOT NULL
);


ALTER TABLE public.users OWNER TO postgres;

--
-- Name: dovecot_users; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.dovecot_users AS
 SELECT users.id,
    concat(users.email, '@', domains.name) AS username,
    concat(users.dovecot_type, users.password) AS password,
    concat('/var/mail/vhosts/', domains.id, '/', users.id, '/home') AS home,
    concat('maildir:/var/mail/', domains.id, '/', users.id) AS mail_location,
    concat('*:bytes=', users.quota_limit_bytes) AS quota_rule,
    system_config.uid,
    system_config.gid
   FROM public.system_config,
    (public.users
     JOIN public.flattened_domains domains ON (((domains.id = users.domain_id) AND (domains.deleted = false))))
  WHERE (users.deleted = false);


ALTER VIEW public.dovecot_users OWNER TO postgres;

--
-- Name: web_domain_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.web_domain_permissions (
    user_id bigint NOT NULL,
    domain_id bigint NOT NULL,
    admin boolean,
    view_domain boolean,
    create_subdomain boolean,
    delete_subdomain boolean,
    list_accounts boolean,
    create_accounts boolean,
    modify_accounts boolean,
    create_alias boolean,
    delete_alias boolean,
    list_permissions boolean,
    manage_permissions boolean,
    list_subdomain boolean,
    delete_accounts boolean,
    modify_domain boolean,
    list_alias boolean,
    list_deleted boolean,
    undelete boolean,
    delete_disabled boolean
);


ALTER TABLE public.web_domain_permissions OWNER TO postgres;

--
-- Name: flattened_web_domain_permissions; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.flattened_web_domain_permissions AS
 SELECT users.id AS user_id,
    domains.id AS domain_id,
    domains.name AS domain_name,
    domains.super AS domain_super,
    COALESCE((users.id = domains.domain_owner[1]), false) AS is_owner,
    COALESCE((users.id = domains.domain_owner[2]), false) AS super_owner,
    COALESCE((ARRAY( SELECT perm.admin
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.admin IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS admin,
    COALESCE((ARRAY( SELECT perm.view_domain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.view_domain IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS view_domain,
    COALESCE((ARRAY( SELECT perm.modify_domain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.modify_domain IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS modify_domain,
    COALESCE((ARRAY( SELECT perm.list_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_subdomain IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS list_subdomain,
    COALESCE((ARRAY( SELECT perm.create_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_subdomain IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS create_subdomain,
    COALESCE((ARRAY( SELECT perm.delete_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_subdomain IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS delete_subdomain,
    COALESCE((ARRAY( SELECT perm.list_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_accounts IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS list_accounts,
    COALESCE((ARRAY( SELECT perm.create_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_accounts IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS create_accounts,
    COALESCE((ARRAY( SELECT perm.modify_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.modify_accounts IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS modify_accounts,
    COALESCE((ARRAY( SELECT perm.delete_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_accounts IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS delete_accounts,
    COALESCE((ARRAY( SELECT perm.list_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_alias IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS list_alias,
    COALESCE((ARRAY( SELECT perm.create_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_alias IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS create_alias,
    COALESCE((ARRAY( SELECT perm.delete_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_alias IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS delete_alias,
    COALESCE((ARRAY( SELECT perm.list_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_permissions IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS list_permissions,
    COALESCE((ARRAY( SELECT perm.manage_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.manage_permissions IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS manage_permissions,
    COALESCE((ARRAY( SELECT perm.list_deleted
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_deleted IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS list_deleted,
    COALESCE((ARRAY( SELECT perm.undelete
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.undelete IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS undelete,
    COALESCE((ARRAY( SELECT perm.delete_disabled
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_disabled IS NOT NULL))
          ORDER BY td.level DESC))[1], false) AS delete_disabled
   FROM public.flattened_domains domains,
    public.users;


ALTER VIEW public.flattened_web_domain_permissions OWNER TO postgres;

--
-- Name: virtual_aliases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.virtual_aliases (
    id bigint NOT NULL,
    domain_id bigint NOT NULL,
    source text NOT NULL,
    destination bigint NOT NULL
);


ALTER TABLE public.virtual_aliases OWNER TO postgres;

--
-- Name: virtual_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.virtual_domains AS
 SELECT id,
    name,
    super,
    domain_owner,
    accepts_email,
    level
   FROM public.flattened_domains
  WHERE (deleted = false)
  WITH CASCADED CHECK OPTION;


ALTER VIEW public.virtual_domains OWNER TO postgres;

--
-- Name: postfix_alias; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.postfix_alias AS
 SELECT concat(alias.source, '@', domains.name) AS alias,
    users.username AS target
   FROM ((public.virtual_aliases alias
     JOIN public.virtual_domains domains ON ((alias.domain_id = domains.id)))
     JOIN public.dovecot_users users ON ((alias.destination = users.id)));


ALTER VIEW public.postfix_alias OWNER TO postgres;

--
-- Name: postfix_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.postfix_domains AS
 SELECT name
   FROM public.flattened_domains
  WHERE ((accepts_email = true) AND (deleted = false));


ALTER VIEW public.postfix_domains OWNER TO postgres;

--
-- Name: user_permission; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_permission (
    id bigint NOT NULL,
    self_change_password boolean DEFAULT true NOT NULL
);


ALTER TABLE public.user_permission OWNER TO postgres;

--
-- Name: users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.users ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: virtual_aliases_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.virtual_aliases ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.virtual_aliases_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Name: virtual_user_permission; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.virtual_user_permission AS
 SELECT users.id,
    users.deleted,
    COALESCE(user_permission.self_change_password, true) AS self_change_password
   FROM (public.users
     LEFT JOIN public.user_permission ON ((users.id = user_permission.id)));


ALTER VIEW public.virtual_user_permission OWNER TO postgres;

--
-- Name: virtual_users; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.virtual_users AS
 SELECT id,
    domain_id,
    email,
    password,
    dovecot_type
   FROM public.users
  WHERE (deleted = false)
  WITH LOCAL CHECK OPTION;


ALTER VIEW public.virtual_users OWNER TO postgres;

--
-- Name: user_permission user_permission_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permission
    ADD CONSTRAINT user_permission_pkey PRIMARY KEY (id);


--
-- Name: virtual_aliases virtual_aliases_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_aliases
    ADD CONSTRAINT virtual_aliases_pkey PRIMARY KEY (id);


--
-- Name: domains virtual_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT virtual_domains_pkey PRIMARY KEY (id);


--
-- Name: users virtual_users_domain_id_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT virtual_users_domain_id_email_key UNIQUE (domain_id, email);


--
-- Name: users virtual_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT virtual_users_pkey PRIMARY KEY (id);


--
-- Name: web_domain_permissions web_domain_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_pkey PRIMARY KEY (user_id, domain_id);


--
-- Name: domains_super_name_uindex; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX domains_super_name_uindex ON public.domains USING btree (super, name);


--
-- Name: virtual_aliases_domain_id_source_index; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX virtual_aliases_domain_id_source_index ON public.virtual_aliases USING btree (domain_id, source);


--
-- Name: flattened_domains flattened_domains_delete; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER flattened_domains_delete INSTEAD OF DELETE ON public.flattened_domains FOR EACH ROW EXECUTE FUNCTION public.mark_deleted('domains', 'deleted', 'id');


--
-- Name: virtual_domains virtual_domains_delete; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER virtual_domains_delete INSTEAD OF DELETE ON public.virtual_domains FOR EACH ROW EXECUTE FUNCTION public.mark_deleted('domains', 'deleted', 'id');


--
-- Name: virtual_users virtual_users_delete; Type: TRIGGER; Schema: public; Owner: postgres
--

CREATE TRIGGER virtual_users_delete INSTEAD OF DELETE ON public.virtual_users FOR EACH ROW EXECUTE FUNCTION public.mark_deleted('users', 'deleted', 'id');


--
-- Name: domains domains_users_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_users_id_fk FOREIGN KEY (domain_owner) REFERENCES public.users(id);


--
-- Name: user_permission user_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permission
    ADD CONSTRAINT user_permission_id_fkey FOREIGN KEY (id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: virtual_aliases virtual_aliases_destination_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_aliases
    ADD CONSTRAINT virtual_aliases_destination_fkey FOREIGN KEY (destination) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: virtual_aliases virtual_aliases_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_aliases
    ADD CONSTRAINT virtual_aliases_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: domains virtual_domains_super_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT virtual_domains_super_fkey FOREIGN KEY (super) REFERENCES public.domains(id);


--
-- Name: users virtual_users_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT virtual_users_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: web_domain_permissions web_domain_permissions_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;


--
-- Name: web_domain_permissions web_domain_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: DATABASE mailserver; Type: ACL; Schema: -; Owner: postgres
--

GRANT CONNECT ON DATABASE mailserver TO mailuser;


--
-- Name: TABLE domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.domains TO mailuser;


--
-- Name: TABLE flattened_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,DELETE ON TABLE public.flattened_domains TO mailuser;


--
-- Name: TABLE users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.users TO mailuser;


--
-- Name: TABLE dovecot_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,DELETE ON TABLE public.dovecot_users TO mailuser;


--
-- Name: TABLE web_domain_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.web_domain_permissions TO mailuser;


--
-- Name: TABLE flattened_web_domain_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.flattened_web_domain_permissions TO mailuser;


--
-- Name: TABLE virtual_aliases; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_aliases TO mailuser;


--
-- Name: TABLE virtual_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,DELETE ON TABLE public.virtual_domains TO mailuser;


--
-- Name: TABLE postfix_alias; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.postfix_alias TO mailuser;


--
-- Name: TABLE postfix_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,DELETE ON TABLE public.postfix_domains TO mailuser;


--
-- Name: TABLE user_permission; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.user_permission TO mailuser;


--
-- Name: TABLE virtual_user_permission; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.virtual_user_permission TO mailuser;


--
-- Name: TABLE virtual_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_users TO mailuser;


--
-- PostgreSQL database dump complete
--

