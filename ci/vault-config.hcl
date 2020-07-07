storage "file" {
  path    = "/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

log_level: "Info"

telemetry {
  statsite_address = "127.0.0.1:8125"
  disable_hostname = true
}
