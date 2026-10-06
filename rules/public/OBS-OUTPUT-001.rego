package observatory.output

default open_world_untyped := false
open_world_untyped if {
  input.facts["output.open_world_untyped_tool_count"] > 0
}
