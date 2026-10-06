package observatory.tools

default annotation_conflict := false
annotation_conflict if {
  input.facts["classification.annotation_conflict_count"] > 0
}
