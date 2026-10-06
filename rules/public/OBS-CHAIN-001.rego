package observatory.chain

default risky_combination := false
risky_combination if {
  input.facts["risk_chain.count"] > 0
}
