package observatory.input

default unconstrained_sinks := false
unconstrained_sinks if {
  input.facts["input.unconstrained_sink_tool_count"] > 0
}
