#!/bin/bash
PGPASSWORD='xmpp-test-password' psql -U xmpp_test -d xmpp_test -h 127.0.0.1 -c "\d users"
echo "=== SCRAM data ==="
PGPASSWORD='xmpp-test-password' psql -U xmpp_test -d xmpp_test -h 127.0.0.1 -c "SELECT username, scram_salt IS NOT NULL as has_scram, scram_iterations FROM users LIMIT 5;"
