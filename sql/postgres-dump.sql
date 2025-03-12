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
    undelete boolean
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
    (users.id = ANY (domains.domain_owner)) AS is_owner,
    (array_append(ARRAY( SELECT perm.admin
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.admin IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS admin,
    (array_append(ARRAY( SELECT perm.view_domain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.view_domain IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS view_domain,
    (array_append(ARRAY( SELECT perm.modify_domain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.modify_domain IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS modify_domain,
    (array_append(ARRAY( SELECT perm.list_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_subdomain IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS list_subdomain,
    (array_append(ARRAY( SELECT perm.create_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_subdomain IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS create_subdomain,
    (array_append(ARRAY( SELECT perm.delete_subdomain
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_subdomain IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS delete_subdomain,
    (array_append(ARRAY( SELECT perm.list_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_accounts IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS list_accounts,
    (array_append(ARRAY( SELECT perm.create_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_accounts IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS create_accounts,
    (array_append(ARRAY( SELECT perm.modify_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.modify_accounts IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS modify_accounts,
    (array_append(ARRAY( SELECT perm.delete_accounts
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_accounts IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS delete_accounts,
    (array_append(ARRAY( SELECT perm.create_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.create_alias IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS create_alias,
    (array_append(ARRAY( SELECT perm.delete_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.delete_alias IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS delete_alias,
    (array_append(ARRAY( SELECT perm.list_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_permissions IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS list_permissions,
    (array_append(ARRAY( SELECT perm.manage_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.manage_permissions IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS manage_permissions,
    (array_append(ARRAY( SELECT perm.list_alias
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_alias IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS list_alias,
    (array_append(ARRAY( SELECT perm.list_deleted
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.list_deleted IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS list_deleted,
    (array_append(ARRAY( SELECT perm.undelete
           FROM (public.web_domain_permissions perm
             JOIN public.flattened_domains td ON (((td.id = domains.id) OR (td.id = ANY (domains.super)))))
          WHERE ((perm.user_id = users.id) AND (perm.domain_id = td.id) AND (perm.undelete IS NOT NULL))
          ORDER BY td.level DESC), false))[1] AS undelete
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
-- Name: domains_name_uindex; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX domains_name_uindex ON public.domains USING btree (name);


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

