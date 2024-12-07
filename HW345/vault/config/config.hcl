listener "tcp" {
  address     = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/vault/certs/server.crt"
  tls_key_file  = "/vault/certs/server.key"
}

api_addr = "https://localhost:8200"
cluster_addr = "https://localhost:8201"

storage "file" {
  path = "/vault/data"
}

disable_mlock = true
ui = true