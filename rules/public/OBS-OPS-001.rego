package observatory.ops

default high_latency := false
high_latency if {
  input.facts["operational.average_latency_ms"] > 500
}
