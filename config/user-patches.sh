#Make dovecot use sql auth
sed -i "s|!include auth-passwdfile.inc|#!include auth-passwdfile.inc|" /etc/dovecot/conf.d/10-auth.conf
sed -i "s|#!include auth-sql.conf.ext|!include /tmp/docker-mailserver/dovecot/auth-sql.conf.ext|" /etc/dovecot/conf.d/10-auth.conf

#Make opendkim pull keys from sql
sed -Ei -e 's|^(SigningTable\s*)(.*)|\1dsn:pgsql://user:passwd@ip/port+mailserver/table=dkim_enabled_domains?keycol=domain_name?datacol=id|' -e 's|^(KeyTable\s*)(.*)|\1dsn:pgsql://user:passwd@ip/port+mailserver/table=dkimkeys?keycol=id?datacol=domain_name,selector,private_key|' /etc/opendkim.conf


apt update && apt install postfix-pgsql dovecot-pgsql libopendbx1-pgsql -y
