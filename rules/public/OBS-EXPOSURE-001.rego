package observatory.exposure

default anonymous_destructive := false
anonymous_destructive if {
  input.facts["exposure.destructive_anonymous_count"] > 0
}
