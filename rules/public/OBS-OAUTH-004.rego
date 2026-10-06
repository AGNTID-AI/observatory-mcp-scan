package observatory.oauth

default registration_path_missing := false
registration_path_missing if {
  object.get(input.facts, "oauth.detected", false) == true
  object.get(input.facts, "oauth.authorization_server_metadata_valid", false) == true
  object.get(input.facts, "oauth.dcr_supported", false) == false
  object.get(input.facts, "oauth.client_id_metadata_document_supported", false) == false
}
