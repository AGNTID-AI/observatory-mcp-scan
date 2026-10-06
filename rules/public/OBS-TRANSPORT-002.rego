package observatory.transport

default hsts_missing := false
hsts_missing if {
  input.facts["transport.https"] == true
  input.facts["transport.hsts"] == false
}
