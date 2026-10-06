package observatory.content

default medium_signals := false
medium_signals if {
  input.facts["content.medium_count"] > 0
}
