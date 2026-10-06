package observatory.oauth

default pkce_s256_missing := false
pkce_s256_missing if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.authorization_server_metadata_valid", false) == true
  object.get(input.facts, "oauth.pkce_s256", false) == false
}
