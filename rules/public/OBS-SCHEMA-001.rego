package observatory.schema

default loose_schemas := false
loose_schemas if {
  input.facts["schema.loose_tool_count"] > 0
}
