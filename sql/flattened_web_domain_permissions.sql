CREATE OR REPLACE VIEW flattened_web_domain_permissions
    AS with recursive test as (
      SELECT
          perm.user_id as user_id,
          perm.domain_id as domain_id,
          COALESCE(perm.admin, false) as admin,
          COALESCE(perm.web_login, false) as web_login,
          COALESCE(perm.view_domain, false) as view_domain,
          COALESCE(perm.create_subdomain, false) as create_subdomain,
          COALESCE(perm.delete_subdomain, false) as delete_subdomain,
          COALESCE(perm.list_accounts, false) as list_accounts,
          COALESCE(perm.create_accounts, false) as create_accounts,
          COALESCE(perm.modify_accounts, false) as modify_accounts,
          COALESCE(perm.create_alias, false) as create_alias,
          COALESCE(perm.modify_alias, false) as modify_alias,
          COALESCE(perm.list_permissions, 0) as list_permissions,
          COALESCE(perm.manage_permissions, 0) as manage_permissions
      FROM web_domain_permissions perm
               JOIN virtual_domains domain ON perm.domain_id = domain.id
                WHERE domain.id = domain.super
      UNION ALL
          SELECT
              rec.user_id as user_id,
              this_domain.id as domain_id,
              COALESCE(perm.admin, rec.admin, false) as admin,
              COALESCE(perm.web_login, rec.web_login, false) as web_login,
              COALESCE(perm.view_domain, rec.view_domain, false) as view_domain,
              COALESCE(perm.create_subdomain, rec.create_subdomain, false) as create_subdomain,
              COALESCE(perm.delete_subdomain, rec.delete_subdomain, false) as delete_subdomain,
              COALESCE(perm.list_accounts, rec.list_accounts, false) as list_accounts,
              COALESCE(perm.create_accounts, rec.create_accounts, false) as create_accounts,
              COALESCE(perm.modify_accounts, rec.modify_accounts, false) as modify_accounts,
              COALESCE(perm.create_alias, rec.create_alias, false) as create_alias,
              COALESCE(perm.modify_alias, rec.modify_alias, false) as modify_alias,
              COALESCE(perm.list_permissions, rec.list_permissions, 0) as list_permissions,
              COALESCE(perm.manage_permissions, rec.manage_permissions, 0) as manage_permissions
      FROM test rec
            INNER JOIN virtual_domains this_domain ON rec.domain_id = this_domain.super AND this_domain.super != this_domain.id
            LEFT JOIN web_domain_permissions perm ON perm.user_id = rec.user_id AND perm.domain_id = this_domain.id
) select * from test;