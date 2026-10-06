package observatory.oauth

default resource_metadata_missing := false
resource_metadata_missing if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.resource_metadata_valid", false) == false
}
