package observatory.ai

default context_heavy := false
context_heavy if {
  input.facts["ai.context_utilization"] > 15
}
