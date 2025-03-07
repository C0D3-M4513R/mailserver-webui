WITH RECURSIVE test AS (SELECT perm.user_id,
                               perm.domain_id,
                               domain.name                              AS domain_name,
                               COALESCE(perm.admin, false)              AS admin,
                               COALESCE(perm.web_login, false)          AS web_login,
                               COALESCE(perm.view_domain, false)        AS view_domain,
                               COALESCE(perm.list_subdomain, false)     AS list_subdomain,
                               COALESCE(perm.create_subdomain, false)   AS create_subdomain,
                               COALESCE(perm.delete_subdomain, false)   AS delete_subdomain,
                               COALESCE(perm.list_accounts, false)      AS list_accounts,
                               COALESCE(perm.create_accounts, false)    AS create_accounts,
                               COALESCE(perm.modify_accounts, false)    AS modify_accounts,
                               COALESCE(perm.create_alias, false)       AS create_alias,
                               COALESCE(perm.modify_alias, false)       AS modify_alias,
                               COALESCE(perm.list_permissions, false)   AS list_permissions,
                               COALESCE(perm.manage_permissions, false) AS manage_permissions
                        FROM web_domain_permissions perm
                                 JOIN virtual_domains domain ON perm.domain_id = domain.id
                        WHERE domain.id = domain.super
                        UNION ALL
                        SELECT rec.user_id,
                               this_domain.id                                                   AS domain_id,
                               this_domain.name                                                 AS domain_name,
                               COALESCE(perm.admin, rec.admin, false)                           AS admin,
                               COALESCE(perm.web_login, rec.web_login, false)                   AS web_login,
                               COALESCE(perm.view_domain, rec.view_domain, false)               AS view_domain,
                               COALESCE(perm.list_subdomain, rec.list_subdomain, false)         AS list_subdomain,
                               COALESCE(perm.create_subdomain, rec.create_subdomain, false)     AS create_subdomain,
                               COALESCE(perm.delete_subdomain, rec.delete_subdomain, false)     AS delete_subdomain,
                               COALESCE(perm.list_accounts, rec.list_accounts, false)           AS list_accounts,
                               COALESCE(perm.create_accounts, rec.create_accounts, false)       AS create_accounts,
                               COALESCE(perm.modify_accounts, rec.modify_accounts, false)       AS modify_accounts,
                               COALESCE(perm.create_alias, rec.create_alias, false)             AS create_alias,
                               COALESCE(perm.modify_alias, rec.modify_alias, false)             AS modify_alias,
                               COALESCE(perm.list_permissions, rec.list_permissions, false)     AS list_permissions,
                               COALESCE(perm.manage_permissions, rec.manage_permissions, false) AS manage_permissions
                        FROM test rec
                                 JOIN virtual_domains this_domain
                                      ON rec.domain_id = this_domain.super AND this_domain.super <> this_domain.id
                                 LEFT JOIN web_domain_permissions perm
                                           ON perm.user_id = rec.user_id AND perm.domain_id = this_domain.id)
SELECT user_id,
       domain_id,
       domain_name,
       admin,
       web_login,
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
FROM test