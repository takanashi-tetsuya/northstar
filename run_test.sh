#!/bin/bash
cd /mnt/c/Users/Admin/Documents/XMPP
python3 test_muc_raw.py 2>&1
RC=$?
echo ""
echo "TEST_EXIT_CODE=$RC"
echo ""
echo "--- SERVER LOG (recent MUC entries) ---"
grep -i "muc\|affil\|admin_set" /tmp/xmpp_server.log | tail -10
