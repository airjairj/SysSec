# Configura il backend di archiviazione su file system
storage "file" {
  path = "C:\\Users\\hp\\Documents\\Esami In Corso\\System Sec\\Homework\\SysSec\\HW4\\vault\\storage"
}

# Configura il listener TCP per Vault
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = 1
}

# Configura l'API address di Vault
api_addr = "http://127.0.0.1:8200"

# Configura la lettura dei segreti dal percorso "secret/*"
path "secret/*" {
  capabilities = ["read"]
}

# Configura la lettura e gestione dei percorsi LDAP tramite la CLI (non nel file HCL)
path "auth/ldap/*" {
  capabilities = ["create", "update", "read", "list"]
}
