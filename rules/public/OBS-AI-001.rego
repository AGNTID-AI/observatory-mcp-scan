package observatory.ai

default missing_descriptions := false
missing_descriptions if {
  input.facts["ai.missing_descriptions"] > 0
}
