# my-policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read"]
}
