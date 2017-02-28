# Shibboleth IdP JWT authentication module

## Build and install

```
git clone https://scm.icts.kuleuven.be/icts/git/idp.idp-authn-jwt.git
mvn package
```

## Configuration

Edit the following properties to $IDP_HOME/conf/jwt.properties (usually /opt/shibboleth-idp)

```
idp.authn.jwt.issuer=https://account.kuleuven.be
idp.authn.jwt.issuer_pubkey=
idp.authn.jwt.expiration=PT3M
idp.authn.jwt.privatekey=
idp.authn.jwt.publickey=
idp.authn.jwt.jws.algorithms=ES512
idp.authn.jwt.jwe.algorithms=ECDH-ES+A256KW
idp.authn.jwt.jwe.enc_methods=A256GCM
idp.authn.jwt.cookie_name=jwt_idp
```

Import jwt.properties in idp.properties
```
# Load any additional property resources from a comma-delimited list
idp.additionalProperties= /conf/ldap.properties, /conf/saml-nameid.properties, /conf/services.properties, /conf/jwt.properties
```

Enable jwt by adding it to the authentication flows, e.g.: 
```
idp.authn.flows=jwt|Password
```

### General authentication

### Dependencies

Install jars of dependencies at $IDP_HOME/edit-webapp/WEB-INF/lib/

Add the following bean to $IDP_HOME/conf/authn/general-authn.xml

In list "shibboleth.AvailableAuthenticationFlows":
```
        <bean id="authn/jwt" parent="shibboleth.AuthenticationFlow"
                p:passiveAuthenticationSupported="false"
                p:forcedAuthenticationSupported="false">
            <property name="supportedPrincipals">
                <util:list>
                    <bean parent="shibboleth.SAML2AuthnContextClassRef"
                        c:classRef="urn:oasis:names:tc:SAML:2.0:ac:classes:jwt" />
                </util:list>
            </property>
        </bean>
```



