package observatory.readiness

default low_score_tools := false
low_score_tools if {
  input.facts["readiness.low_score_tools"] > 0
}
