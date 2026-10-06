package observatory.oauth

default authorization_metadata_invalid := false
authorization_metadata_invalid if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.resource_metadata_valid", false) == true
  object.get(input.facts, "oauth.authorization_server_metadata_valid", false) == false
}
