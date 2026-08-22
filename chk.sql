SELECT u.username, p.node FROM pep_items p JOIN users u ON u.id = p.owner_id WHERE p.node LIKE %omemo%;
