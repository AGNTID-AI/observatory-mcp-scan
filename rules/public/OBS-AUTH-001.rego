package observatory.auth

default anonymous := false
anonymous if {
  input.facts["auth.anonymous"] == true
}
