package observatory.transport

default insecure := false
insecure if {
  input.facts["transport.https"] == false
}
