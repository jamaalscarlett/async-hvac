backend "inmem" {
}

listener "tcp" {
  tls_cert_file = "test-fixtures/server-cert.pem"
  tls_key_file  = "test-fixtures/server-key.pem"
}

disable_mlock = true

default_lease_ttl = "768h"
max_lease_ttl = "768h"
