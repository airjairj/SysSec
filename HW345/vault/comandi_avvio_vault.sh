# serve aggiungere questo ad ogni comando:    
    #prima
    $env:VAULT_SKIP_VERIFY="true"; 
    #dopo
    -address=https://localhost:8200

# Root token: hvs.0rS1idLr8xPrnoyZPBGMx04W
# Unseal Key 1: raYvzSUsi5mI0wQrP26BpFskyUrP5txsfYI5SjguY1Ov
# Unseal Key 2: 7kP1aDZqH+1ITFdqAF1cP6SfZ/ZB5K+EyEpTbtk4Xv6N
# Unseal Key 3: k1+1pmykUM4PD2hm6aQjwEI2aa09Ojb1W2MFahaLQX89
# Unseal Key 4: yZFYT/DMCvFQucwUvjDYljLTR82cz/QRiz4ok69DvsZT
# Unseal Key 5: 3UKJD7DXfiqORInDld8sYweqP/II36k+1436HLn8SjyP

# Solo la prima volta
vault operator init -address=https://localhost:8200

# Ogni volta
$env:VAULT_SKIP_VERIFY="true"; vault operator unseal -address=https://localhost:8200 raYvzSUsi5mI0wQrP26BpFskyUrP5txsfYI5SjguY1Ov
$env:VAULT_SKIP_VERIFY="true"; vault operator unseal -address=https://localhost:8200 7kP1aDZqH+1ITFdqAF1cP6SfZ/ZB5K+EyEpTbtk4Xv6N 
$env:VAULT_SKIP_VERIFY="true"; vault operator unseal -address=https://localhost:8200 k1+1pmykUM4PD2hm6aQjwEI2aa09Ojb1W2MFahaLQX89
$env:VAULT_SKIP_VERIFY="true"; vault login -address=https://localhost:8200 hvs.0rS1idLr8xPrnoyZPBGMx04W

# Solo la prima volta
vault auth enable -address=https://localhost:8200 ldap
vault write -address=https://localhost:8200  auth/ldap/config url="ldap://ldap:389" binddn="cn=admin,dc=example,dc=com" bindpass="adminpassword" userdn="dc=example,dc=com" groupdn="dc=example,dc=com" userattr="cn" insecure_tls=true tls_cert_file="/vault/certs/ldap.crt"

vault policy write -address=https://localhost:8200 utenti "/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/vault/utenti.hcl"
vault policy write -address=https://localhost:8200 amministratori "/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/vault/amministratori.hcl"

vault write -address=https://localhost:8200 auth/ldap/groups/utenti policies="utenti"
vault write -address=https://localhost:8200 auth/ldap/groups/amministratori policies="amministratori"

# Test
vault login -address=https://localhost:8200 -tls-skip-verify -method=ldap username="TIZIO" password="TIZIO"
vault kv put secret/mysecret value="HelloWorld" # Deve funzionare

# CERTIFICATI #
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Org/CN=localhost"

#********* MAC *********#

# Solo la prima volta
vault operator init -address=https://localhost:8200 -tls-skip-verify

# Ogni volta
vault operator unseal -address=https://localhost:8200 -tls-skip-verify raYvzSUsi5mI0wQrP26BpFskyUrP5txsfYI5SjguY1Ov
vault operator unseal -address=https://localhost:8200 -tls-skip-verify 7kP1aDZqH+1ITFdqAF1cP6SfZ/ZB5K+EyEpTbtk4Xv6N 
vault operator unseal -address=https://localhost:8200 -tls-skip-verify k1+1pmykUM4PD2hm6aQjwEI2aa09Ojb1W2MFahaLQX89
vault login -address=https://localhost:8200 -tls-skip-verify hvs.0rS1idLr8xPrnoyZPBGMx04W

# Solo la prima volta
vault auth enable -address=https://localhost:8200 -tls-skip-verify ldap
vault write -address=https://localhost:8200 -tls-skip-verify auth/ldap/config url="ldap://ldap:389" binddn="cn=admin,dc=example,dc=com" bindpass="adminpassword" userdn="dc=example,dc=com" groupdn="dc=example,dc=com" userattr="cn" insecure_tls=true tls_cert_file="/vault/certs/ldap.crt"

vault policy write -address=https://localhost:8200 -tls-skip-verify utenti "/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/vault/utenti.hcl"
vault policy write -address=https://localhost:8200 -tls-skip-verify amministratori "/Users/francescoavallone/Desktop/UNIVERSITA/SystemSecurity/SysSec/HW345/vault/amministratori.hcl"

vault write -address=https://localhost:8200 -tls-skip-verify auth/ldap/groups/utenti policies="utenti"
vault write -address=https://localhost:8200 -tls-skip-verify auth/ldap/groups/amministratori policies="amministratori"

#Abilitazione OIDC e JWT

vault auth enable  -address=https://localhost:8200 -tls-skip-verify oidc

vault auth enable  -address=https://localhost:8200 -tls-skip-verify jwt

#Configurazione oidc
vault write -address=https://localhost:8200 -tls-skip-verify auth/jwt/config \
  oidc_discovery_url="https://accounts.google.com" \
  bound_issuer="https://accounts.google.com" \
  oidc_client_id="" \
  oidc_client_secret="" \
  default_role="utente" 

#Creazione ruoli
vault write -address=https://localhost:8200 -tls-skip-verify auth/jwt/role/utente \
  allowed_redirect_uris="https://localhost:5173/callback" \
  user_claim="sub" \
  role_type="jwt" \
  bound_audiences="292219212098-q10f6k4mgjkp8lj7v0drpu0hqdpsrqfr.apps.googleusercontent.com" \
  policies="utenti"

vault write -address=https://localhost:8200 -tls-skip-verify auth/jwt/role/amministratore \
  allowed_redirect_uris="https://localhost:5173/callback" \
  user_claim="sub" \
  role_type="jwt" \
  bound_audiences="292219212098-q10f6k4mgjkp8lj7v0drpu0hqdpsrqfr.apps.googleusercontent.com" \
  policies="amministratori"
 
  
  #Test
  vault read -address=https://localhost:8200 -tls-skip-verify auth/oidc/role/utente | grep allowed_redirect_uris

  vault auth list -address=https://localhost:8200 -tls-skip-verify 

  vault list -address=https://localhost:8200 -tls-skip-verify auth/oidc/role

  vault read -address=https://localhost:8200 -tls-skip-verify auth/oidc/config

  vault token lookup -address=https://localhost:8200 -tls-skip-verify

  vault token -address=https://localhost:8200 -tls-skip-verify capabilities hvs.0rS1idLr8xPrnoyZPBGMx04W auth/oidc/login

  vault server -address=https://localhost:8200 -tls-skip-verify -dev

  vault login -address=https://localhost:8200 -tls-skip-verify -method=oidc role=utente

  vault audit enable -address=https://localhost:8200 -tls-skip-verify file file_path=/tmp/vault_audit.log


