# Contract fixtures

This directory holds immutable Protobuf wire fixtures for security assertions,
session fencing, ingress admission, and event envelopes.  Text `.hex` files
are used in source control so reviewers can inspect the exact bytes; the
fixture harness decodes them to binary before comparison.  A fixture name
contains the package and schema version, for example
`northstar.security.v1.auth-grant.hex`.

When a field is added, retain the old fixture and add a new case.  Never replace
an existing fixture to make a failing compatibility test pass.
