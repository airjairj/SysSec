docker exec -it ldap /bin/bash

echo "dn: cn=TIZIO,dc=example,dc=com
objectClass: top
objectClass: person
cn: TIZIO
sn: SURNAME
userPassword: TIZIO

dn: cn=TIZIO_ADMIN,dc=example,dc=com
objectClass: top
objectClass: person
cn: TIZIO_ADMIN
sn: SURNAME
userPassword: TIZIO_ADMIN

dn: cn=utenti,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: utenti
member: cn=TIZIO,dc=example,dc=com

dn: cn=amministratori,dc=example,dc=com
objectClass: top
objectClass: groupOfNames
cn: amministratori
member: cn=TIZIO_ADMIN,dc=example,dc=com" > /tmp/init.ldif

ldapadd -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w adminpassword -f /tmp/init.ldif

ldapsearch -x -H ldap://localhost:389 -D "cn=admin,dc=example,dc=com" -w adminpassword -b "dc=example,dc=com"

# CERTIFICATI #
openssl req -x509 -newkey rsa:2048 -keyout ldap-server.key -out ldap-server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=ldap" -addext "subjectAltName=DNS:ldap"