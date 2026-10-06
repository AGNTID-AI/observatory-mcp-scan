package observatory.drift

default high_risk_changes := false
high_risk_changes if {
  input.facts["drift.high_risk_changes"] > 0
}
