package observatory.content

default high_signals := false
high_signals if {
  input.facts["content.high_count"] > 0
}
