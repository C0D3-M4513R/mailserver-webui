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

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: virtual_domains; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.virtual_domains (
    id integer NOT NULL,
    name text NOT NULL,
    super integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.virtual_domains OWNER TO postgres;

--
-- Name: flattened_domains; Type: VIEW; Schema: public; Owner: postgres
--

CREATE VIEW public.flattened_domains AS
 WITH RECURSIVE test AS (
         SELECT virtual_domains.id,
            virtual_domains.super
           FROM public.virtual_domains
        UNION ALL
         SELECT domain.id,
            test_1.super
           FROM (public.virtual_domains domain
             JOIN test test_1 ON (((domain.super = test_1.id) AND (test_1.id <> test_1.super))))
        )
 SELECT id,
    super
   FROM test;


ALTER VIEW public.flattened_domains OWNER TO postgres;

--
-- Name: web_domain_permissions; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.web_domain_permissions (
    user_id integer NOT NULL,
    domain_id integer NOT NULL,
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
    list_subdomain boolean
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
            COALESCE(perm.create_alias, false) AS create_alias,
            COALESCE(perm.modify_alias, false) AS modify_alias,
            COALESCE(perm.list_permissions, false) AS list_permissions,
            COALESCE(perm.manage_permissions, false) AS manage_permissions
           FROM (public.web_domain_permissions perm
             JOIN public.virtual_domains domain ON ((perm.domain_id = domain.id)))
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
            COALESCE(perm.create_alias, rec.create_alias, false) AS create_alias,
            COALESCE(perm.modify_alias, rec.modify_alias, false) AS modify_alias,
            COALESCE(perm.list_permissions, rec.list_permissions, false) AS list_permissions,
            COALESCE(perm.manage_permissions, rec.manage_permissions, false) AS manage_permissions
           FROM ((test rec
             JOIN public.virtual_domains this_domain ON (((rec.domain_id = this_domain.super) AND (this_domain.super <> this_domain.id))))
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
    id integer NOT NULL,
    self_change_password boolean DEFAULT true NOT NULL
);


ALTER TABLE public.user_permission OWNER TO postgres;

--
-- Name: virtual_aliases; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.virtual_aliases (
    id integer NOT NULL,
    domain_id integer NOT NULL,
    source text NOT NULL,
    destination integer NOT NULL
);


ALTER TABLE public.virtual_aliases OWNER TO postgres;

--
-- Name: virtual_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.virtual_users (
    id integer NOT NULL,
    domain_id integer NOT NULL,
    password text NOT NULL,
    email text NOT NULL,
    dovecot_type text DEFAULT ''::text NOT NULL
);


ALTER TABLE public.virtual_users OWNER TO postgres;

--
-- Name: virtual_users_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

ALTER TABLE public.virtual_users ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
    SEQUENCE NAME public.virtual_users_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1
);


--
-- Data for Name: user_permission; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.user_permission (id, self_change_password) FROM stdin;
\.


--
-- Data for Name: virtual_aliases; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.virtual_aliases (id, domain_id, source, destination) FROM stdin;
\.


--
-- Data for Name: virtual_domains; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.virtual_domains (id, name, super) FROM stdin;
0	root	0
1	c0d3m4513r.com	0
2	test.c0d3m4513r.com	1
\.


--
-- Data for Name: virtual_users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.virtual_users (id, domain_id, password, email, dovecot_type) FROM stdin;
1	1	test	c0d3m4513r
\.


--
-- Data for Name: web_domain_permissions; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.web_domain_permissions (user_id, domain_id, admin, view_domain, create_subdomain, delete_subdomain, list_accounts, create_accounts, modify_accounts, create_alias, modify_alias, list_permissions, manage_permissions, list_subdomain) FROM stdin;
1	0	t	t	t	t	t	t	t	t	t	t	t	t
1	1	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N	\N
\.


--
-- Name: virtual_users_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.virtual_users_id_seq', 14, true);


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
-- Name: virtual_domains virtual_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_domains
    ADD CONSTRAINT virtual_domains_pkey PRIMARY KEY (id);


--
-- Name: virtual_users virtual_users_domain_id_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_users
    ADD CONSTRAINT virtual_users_domain_id_email_key UNIQUE (domain_id, email);


--
-- Name: virtual_users virtual_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_users
    ADD CONSTRAINT virtual_users_pkey PRIMARY KEY (id);


--
-- Name: web_domain_permissions web_domain_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_pkey PRIMARY KEY (user_id, domain_id);


--
-- Name: virtual_domains_name_uindex; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX virtual_domains_name_uindex ON public.virtual_domains USING btree (name);


--
-- Name: user_permission user_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_permission
    ADD CONSTRAINT user_permission_id_fkey FOREIGN KEY (id) REFERENCES public.virtual_users(id) ON DELETE CASCADE;


--
-- Name: virtual_aliases virtual_aliases_destination_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_aliases
    ADD CONSTRAINT virtual_aliases_destination_fkey FOREIGN KEY (destination) REFERENCES public.virtual_users(id) ON DELETE CASCADE;


--
-- Name: virtual_aliases virtual_aliases_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_aliases
    ADD CONSTRAINT virtual_aliases_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.virtual_domains(id) ON DELETE CASCADE;


--
-- Name: virtual_domains virtual_domains_super_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_domains
    ADD CONSTRAINT virtual_domains_super_fkey FOREIGN KEY (super) REFERENCES public.virtual_domains(id);


--
-- Name: virtual_users virtual_users_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.virtual_users
    ADD CONSTRAINT virtual_users_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.virtual_domains(id) ON DELETE CASCADE;


--
-- Name: web_domain_permissions web_domain_permissions_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.virtual_domains(id) ON DELETE CASCADE;


--
-- Name: web_domain_permissions web_domain_permissions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.web_domain_permissions
    ADD CONSTRAINT web_domain_permissions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.virtual_users(id) ON DELETE CASCADE;


--
-- Name: TABLE virtual_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_domains TO mailuser;


--
-- Name: TABLE flattened_domains; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.flattened_domains TO mailuser;


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
-- Name: TABLE virtual_users; Type: ACL; Schema: public; Owner: postgres
--

GRANT SELECT,INSERT,DELETE,UPDATE ON TABLE public.virtual_users TO mailuser;


--
-- PostgreSQL database dump complete
--

