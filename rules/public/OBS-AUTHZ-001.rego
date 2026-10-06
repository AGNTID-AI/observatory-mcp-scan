package observatory.authorization

default catalogs_equivalent := false
catalogs_equivalent if {
  input.facts["identity.compared_profiles"] > 1
  input.facts["identity.catalog_equivalent"] == true
}
