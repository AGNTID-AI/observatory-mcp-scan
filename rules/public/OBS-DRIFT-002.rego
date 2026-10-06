package observatory.drift

default catalog_changed := false
catalog_changed if {
  input.facts["drift.compared"] == true
  input.facts["drift.added_count"] + input.facts["drift.removed_count"] + input.facts["drift.modified_count"] > 0
}
