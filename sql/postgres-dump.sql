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
    deleted boolean DEFAULT false NOT NULL
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
 SELECT concat(users.email, '@', domains.name) AS username,
    concat(users.dovecot_type, users.password) AS password,
    concat('/var/mail/vhosts', domains.id, '/', users.id, '/home') AS home,
    concat('*:bytes=', users.quota_limit_bytes) AS quota_rule,
    system_config.uid,
    system_config.gid
   FROM public.system_config,
    (public.users
     JOIN public.domains ON (((domains.id = users.id) AND (domains.deleted = false))))
  WHERE (users.deleted = false);


ALTER VIEW public.dovecot_users OWNER TO postgres;

--
-- Name: flattened_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.flattened_domains AS
 WITH RECURSIVE test AS (
         SELECT domains.id,
            domains.name,
            domains.deleted,
            domains.super
           FROM public.domains
        UNION ALL
         SELECT domain.id,
            domain.name,
            domain.deleted,
            test_1.super
           FROM (public.domains domain
             JOIN test test_1 ON (((domain.super = test_1.id) AND (test_1.id <> test_1.super))))
        )
 SELECT id,
    name,
    deleted,
    super
   FROM test;


ALTER VIEW public.flattened_domains OWNER TO postgres;

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
    modify_alias boolean,
    list_permissions boolean,
    manage_permissions boolean,
    list_subdomain boolean,
    delete_accounts boolean
);


ALTER TABLE public.web_domain_permissions OWNER TO postgres;

--
-- Name: flattened_web_domain_permissions; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.flattened_web_domain_permissions AS
 WITH RECURSIVE test AS (
         SELECT perm.user_id,
            perm.domain_id,
            domain.name AS domain_name,
            COALESCE(perm.admin, false) AS admin,
            COALESCE(perm.view_domain, false) AS view_domain,
            COALESCE(perm.list_subdomain, false) AS list_subdomain,
            COALESCE(perm.create_subdomain, false) AS create_subdomain,
            COALESCE(perm.delete_subdomain, false) AS delete_subdomain,
            COALESCE(perm.list_accounts, false) AS list_accounts,
            COALESCE(perm.create_accounts, false) AS create_accounts,
            COALESCE(perm.modify_accounts, false) AS modify_accounts,
            COALESCE(perm.delete_accounts, false) AS delete_accounts,
            COALESCE(perm.create_alias, false) AS create_alias,
            COALESCE(perm.modify_alias, false) AS modify_alias,
            COALESCE(perm.list_permissions, false) AS list_permissions,
            COALESCE(perm.manage_permissions, false) AS manage_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.domains domain ON ((perm.domain_id = domain.id)))
          WHERE (domain.id = domain.super)
        UNION ALL
         SELECT rec.user_id,
            this_domain.id AS domain_id,
            this_domain.name AS domain_name,
            COALESCE(perm.admin, rec.admin, false) AS admin,
            COALESCE(perm.view_domain, rec.view_domain, false) AS view_domain,
            COALESCE(perm.list_subdomain, rec.list_subdomain, false) AS list_subdomain,
            COALESCE(perm.create_subdomain, rec.create_subdomain, false) AS create_subdomain,
            COALESCE(perm.delete_subdomain, rec.delete_subdomain, false) AS delete_subdomain,
            COALESCE(perm.list_accounts, rec.list_accounts, false) AS list_accounts,
            COALESCE(perm.create_accounts, rec.create_accounts, false) AS create_accounts,
            COALESCE(perm.modify_accounts, rec.modify_accounts, false) AS modify_accounts,
            COALESCE(perm.delete_accounts, rec.delete_accounts, false) AS delete_accounts,
            COALESCE(perm.create_alias, rec.create_alias, false) AS create_alias,
            COALESCE(perm.modify_alias, rec.modify_alias, false) AS modify_alias,
            COALESCE(perm.list_permissions, rec.list_permissions, false) AS list_permissions,
            COALESCE(perm.manage_permissions, rec.manage_permissions, false) AS manage_permissions
           FROM ((test rec
             JOIN public.domains this_domain ON (((rec.domain_id = this_domain.super) AND (this_domain.super <> this_domain.id))))
             LEFT JOIN public.web_domain_permissions perm ON (((perm.user_id = rec.user_id) AND (perm.domain_id = this_domain.id))))
        )
 SELECT user_id,
    domain_id,
    domain_name,
    admin,
    view_domain,
    list_subdomain,
    create_subdomain,
    delete_subdomain,
    list_accounts,
    create_accounts,
    modify_accounts,
    delete_accounts,
    create_alias,
    modify_alias,
    list_permissions,
    manage_permissions
   FROM test;


ALTER VIEW public.flattened_web_domain_permissions OWNER TO postgres;

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
    super
   FROM public.domains
  WHERE (deleted = false)
  WITH CASCADED CHECK OPTION;


ALTER VIEW public.virtual_domains OWNER TO postgres;

--
-- Name: virtual_flattened_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.virtual_flattened_domains AS
 SELECT id,
    name,
    super
   FROM public.flattened_domains
  WHERE (deleted = false)
  WITH CASCADED CHECK OPTION;


ALTER VIEW public.virtual_flattened_domains OWNER TO postgres;

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
-- Data for Name: domains; Type: TABLE DATA; Schema: public; Owner: postgres
--

--nope

--
-- Data for Name: user_permission; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: postgres
--

--nope

--
-- Data for Name: virtual_aliases; Type: TABLE DATA; Schema: public; Owner: postgres
--



--
-- Data for Name: web_domain_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

--nope

--
-- Name: domains_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.domains_id_seq', 1, false);


--
-- Name: users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.users_id_seq', 14, true);


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
-- Name: TABLE domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.domains TO mailuser;


--
-- Name: TABLE users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,UPDATE ON TABLE public.users TO mailuser;


--
-- Name: TABLE dovecot_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.dovecot_users TO mailuser;


--
-- Name: TABLE flattened_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.flattened_domains TO mailuser;


--
-- Name: TABLE web_domain_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.web_domain_permissions TO mailuser;


--
-- Name: TABLE flattened_web_domain_permissions; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT ON TABLE public.flattened_web_domain_permissions TO mailuser;


--
-- Name: TABLE user_permission; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.user_permission TO mailuser;


--
-- Name: TABLE virtual_aliases; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_aliases TO mailuser;


--
-- Name: TABLE virtual_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_domains TO mailuser;


--
-- Name: TABLE virtual_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_users TO mailuser;


--
-- PostgreSQL database dump complete
--

