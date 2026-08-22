CREATE TABLE private_xml (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    element_name VARCHAR NOT NULL,
    element_ns VARCHAR NOT NULL,
    xml_data TEXT NOT NULL,
    PRIMARY KEY (user_id, element_name, element_ns)
);
