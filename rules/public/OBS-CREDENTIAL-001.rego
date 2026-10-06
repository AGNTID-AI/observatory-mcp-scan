package observatory.credential

default model_visible := false
model_visible if {
  input.facts["input.credential_parameter_tool_count"] > 0
}
