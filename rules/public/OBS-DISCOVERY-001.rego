package observatory.discovery

default unreachable := false
unreachable if {
	input.facts["discovery.session_established"] == false
}

unreachable if {
	not input.facts["discovery.session_established"]
	input.facts["discovery.reachable"] == false
}
