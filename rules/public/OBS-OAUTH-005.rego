package observatory.oauth

default unsafe_bearer_transport := false
unsafe_bearer_transport if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.unsafe_bearer_methods", false) == true
}
