package observatory.oauth

default scopes_missing := false
scopes_missing if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.resource_metadata_valid", false) == true
  object.get(input.facts, "oauth.scopes_advertised", false) == false
}
