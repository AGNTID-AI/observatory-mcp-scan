package observatory.tools

default high_impact_catalog := false
high_impact_catalog if {
  input.facts["tools.destructive_count"] > 0
}
