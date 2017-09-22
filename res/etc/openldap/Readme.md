
* add schema to /etc/openldap/slapd.conf

    include /etc/openldap/schema/core.schema
    include /etc/openldap/schema/cosine.schema
    include /etc/openldap/schema/inetorgperson.schema
    include /etc/openldap/schema/pam-ocra.schema

assuming
suffix "dc=my-domain,dc=com"
rootdn "cn=root,dc=my-domain,dc=com"

* modify schema

    cp pam-ocra.schema /etc/openldap/schema

* load test data

    service slapd stop
    #!! backup first: slapcat -f /etc/openldap/slapd.conf -l backup.ldif
    slapadd -v -c -l test.ldif -f /etc/openldap/slapd.conf
