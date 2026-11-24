--
-- Seeds two demo connections so the lab works out of the box.
--
-- In both, the password parameter is left as the ${VAULT_SECRET} token: the
-- Vault extension replaces it at connect time — with a one-time SSH password for
-- the SSH connection, and with the KV secret for the RDP connection. You can
-- create/edit connections from the Guacamole admin UI in exactly the same way.
--

-- ---------------------------------------------------------------------------
-- SSH connection -> Vault SSH OTP
-- ---------------------------------------------------------------------------
INSERT INTO guacamole_connection (connection_name, protocol)
VALUES ('ssh-host (Vault SSH OTP)', 'ssh');

SET @cid = LAST_INSERT_ID();

INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES
    (@cid, 'hostname', 'ssh-host'),
    (@cid, 'port',     '22'),
    (@cid, 'username', 'guacuser'),
    (@cid, 'password', '${VAULT_SECRET}');

INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT entity_id, @cid, 'READ'
FROM guacamole_entity
WHERE name = 'guacadmin' AND type = 'USER';

-- ---------------------------------------------------------------------------
-- RDP connection -> Vault KV. The connection name "rdp-host" is what builds the
-- KV path secret/guacamole/rdp/rdp-host.
-- ---------------------------------------------------------------------------
INSERT INTO guacamole_connection (connection_name, protocol)
VALUES ('rdp-host', 'rdp');

SET @cid = LAST_INSERT_ID();

INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES
    (@cid, 'hostname',    'rdp-host'),
    (@cid, 'port',        '3389'),
    (@cid, 'username',    'rdpuser'),
    (@cid, 'password',    '${VAULT_SECRET}'),
    (@cid, 'security',    'any'),
    (@cid, 'ignore-cert', 'true');

INSERT INTO guacamole_connection_permission (entity_id, connection_id, permission)
SELECT entity_id, @cid, 'READ'
FROM guacamole_entity
WHERE name = 'guacadmin' AND type = 'USER';
