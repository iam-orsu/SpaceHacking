-- SpaceVE-1 Mission Database Schema
-- PostgreSQL 16

-- ----------------------------------------------------------------
-- Operators (users)
-- MISCONFIGURATION: passwords stored as MD5 (weak hash)
-- MISCONFIGURATION: all test accounts use 'ops123' or 'admin123'
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS operators (
    id          SERIAL PRIMARY KEY,
    username    VARCHAR(64)  UNIQUE NOT NULL,
    password_md5 CHAR(32)    NOT NULL,   -- MD5(password) — intentionally weak
    role        VARCHAR(32)  NOT NULL,   -- TELEMETRY_OPS|COMMAND_OPS|PAYLOAD_OPS|SAFETY_OPS|ADMIN
    clearance   VARCHAR(16)  NOT NULL DEFAULT 'UNCLASSIFIED',
    full_name   VARCHAR(128),
    email       VARCHAR(128),
    active      BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login  TIMESTAMPTZ
);

-- Seed operator accounts
-- ADMIN: admin / admin123
INSERT INTO operators (username, password_md5, role, clearance, full_name, email)
VALUES
  ('admin',        md5('admin123'),  'ADMIN',         'TOP_SECRET', 'System Administrator',      'admin@orsu.space'),
  ('telemetry.ops', md5('ops123'),   'TELEMETRY_OPS', 'SECRET',     'Dr. Vamsi Krishna',         'vamsi@orsu.space'),
  ('command.ops',  md5('ops123'),    'COMMAND_OPS',   'SECRET',     'Capt. Archana',             'archana@orsu.space'),
  ('payload.ops',  md5('ops123'),    'PAYLOAD_OPS',   'SECRET',     'Dr. Sahithya',              'sahithya@orsu.space'),
  ('safety.ops',   md5('ops123'),    'SAFETY_OPS',    'TOP_SECRET', 'Cmdr. Srinivas',            'srinivas@orsu.space'),
  ('backup.ops',   md5('ops123'),    'COMMAND_OPS',   'SECRET',     'Backup Operator',           'backup@orsu.space')
ON CONFLICT (username) DO NOTHING;

-- ----------------------------------------------------------------
-- Satellites
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS satellites (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(32)  UNIQUE NOT NULL,
    apid        INTEGER      NOT NULL,
    ip_address  INET         NOT NULL,
    inclination FLOAT        NOT NULL,
    raan        FLOAT        NOT NULL DEFAULT 0.0,
    altitude_km FLOAT        NOT NULL DEFAULT 400.0,
    status      VARCHAR(32)  NOT NULL DEFAULT 'NOMINAL',
    added_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

INSERT INTO satellites (name, apid, ip_address, inclination, raan, altitude_km, status)
VALUES
  ('SpaceVE-1A', 512, '192.168.61.100', 51.6,   0.0, 400.0, 'NOMINAL'),
  ('SpaceVE-1B', 513, '192.168.61.101', 51.6, 120.0, 400.0, 'NOMINAL'),
  ('SpaceVE-1C', 514, '192.168.61.102', 97.6, 240.0, 400.0, 'NOMINAL')
ON CONFLICT (name) DO NOTHING;

-- ----------------------------------------------------------------
-- Ground Stations
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ground_stations (
    id          SERIAL PRIMARY KEY,
    name        VARCHAR(32)  UNIQUE NOT NULL,
    ip_address  INET         NOT NULL,
    lat         FLOAT        NOT NULL,
    lon         FLOAT        NOT NULL,
    min_elevation FLOAT      NOT NULL DEFAULT 5.0,
    status      VARCHAR(32)  NOT NULL DEFAULT 'OPERATIONAL',
    maintenance_mode BOOLEAN NOT NULL DEFAULT FALSE
);

INSERT INTO ground_stations (name, ip_address, lat, lon, status, maintenance_mode)
VALUES
  ('GS-ALPHA', '192.168.61.20', 28.5,  -80.5, 'OPERATIONAL', FALSE),
  ('GS-BETA',  '192.168.61.21', 51.5,   -0.1, 'MAINTENANCE', TRUE)
ON CONFLICT (name) DO NOTHING;

-- ----------------------------------------------------------------
-- Telemetry (time-series)
-- Indexed on satellite_id + ts for fast range queries
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS telemetry (
    id           BIGSERIAL    PRIMARY KEY,
    satellite_id VARCHAR(32)  NOT NULL,
    ts           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    battery_soc  FLOAT,
    battery_v    FLOAT,
    solar_a      FLOAT,
    power_w      FLOAT,
    temp_battery FLOAT,
    temp_xpdr    FLOAT,
    temp_payload FLOAT,
    lat          FLOAT,
    lon          FLOAT,
    alt_km       FLOAT,
    eclipse      BOOLEAN,
    mode         VARCHAR(32),
    cpu_pct      FLOAT,
    mem_pct      FLOAT,
    rssi_dbm     FLOAT,
    downlink_db  FLOAT,
    raw          JSONB
);

CREATE INDEX IF NOT EXISTS idx_tlm_sat_ts ON telemetry (satellite_id, ts DESC);

-- Keep only last 24h of detailed telemetry
CREATE OR REPLACE FUNCTION cleanup_old_telemetry() RETURNS void AS $$
BEGIN
    DELETE FROM telemetry WHERE ts < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------
-- Commands
-- Approval workflow: Level 1 = auto, Level 2 = one approver, Level 3 = two
-- MISCONFIGURATION: Level field is advisory only — API doesn't enforce it
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS commands (
    id              BIGSERIAL    PRIMARY KEY,
    satellite_id    VARCHAR(32)  NOT NULL,
    apid            INTEGER      NOT NULL,
    func_code       INTEGER      NOT NULL,
    func_name       VARCHAR(64),
    raw_hex         VARCHAR(64)  NOT NULL,
    level           INTEGER      NOT NULL DEFAULT 1,  -- 1=routine, 2=payload, 3=critical
    status          VARCHAR(32)  NOT NULL DEFAULT 'PENDING',
    submitted_by    VARCHAR(64)  NOT NULL,
    submitted_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    approved_at     TIMESTAMPTZ,
    executed_at     TIMESTAMPTZ,
    notes           TEXT
);

CREATE INDEX IF NOT EXISTS idx_cmd_sat ON commands (satellite_id, submitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_cmd_status ON commands (status);

-- ----------------------------------------------------------------
-- Command approvals (multi-operator sign-off)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS command_approvals (
    id          SERIAL       PRIMARY KEY,
    command_id  BIGINT       REFERENCES commands(id),
    approved_by VARCHAR(64)  NOT NULL,
    approved_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    notes       TEXT
);

-- ----------------------------------------------------------------
-- Incidents (IDS alerts)
-- 10-minute detection lag simulated by incident_response service
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id           BIGSERIAL    PRIMARY KEY,
    severity     VARCHAR(16)  NOT NULL,   -- LOW|MEDIUM|HIGH|CRITICAL
    type         VARCHAR(64)  NOT NULL,   -- UNAUTH_COMMAND|BRUTE_FORCE|ANOMALY|etc
    description  TEXT         NOT NULL,
    source_ip    INET,
    satellite_id VARCHAR(32),
    operator_id  VARCHAR(64),
    occurred_at  TIMESTAMPTZ,
    detected_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at  TIMESTAMPTZ,
    status       VARCHAR(32)  NOT NULL DEFAULT 'OPEN',  -- OPEN|INVESTIGATING|CLOSED
    false_positive BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_incident_det ON incidents (detected_at DESC);

-- ----------------------------------------------------------------
-- Audit log (all operator actions)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL    PRIMARY KEY,
    operator    VARCHAR(64)  NOT NULL,
    action      VARCHAR(128) NOT NULL,
    resource    VARCHAR(128),
    details     JSONB,
    ip_addr     INET,
    ts          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_op ON audit_log (operator, ts DESC);

-- ----------------------------------------------------------------
-- Pass schedule (contact windows)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contact_windows (
    id              SERIAL       PRIMARY KEY,
    satellite_id    VARCHAR(32)  NOT NULL,
    gs_name         VARCHAR(32)  NOT NULL,
    aos_time        TIMESTAMPTZ  NOT NULL,
    los_time        TIMESTAMPTZ  NOT NULL,
    duration_s      INTEGER      NOT NULL,
    max_elevation   FLOAT,
    status          VARCHAR(32)  NOT NULL DEFAULT 'SCHEDULED'
);

CREATE INDEX IF NOT EXISTS idx_cw_time ON contact_windows (aos_time);

-- ----------------------------------------------------------------
-- Seed some historical commands for realism
-- ----------------------------------------------------------------
INSERT INTO commands (satellite_id, apid, func_code, func_name, raw_hex, level, status, submitted_by, submitted_at, executed_at)
VALUES
  ('SpaceVE-1A', 512, 0, 'NOP',           '1a00c0000001 00ff', 1, 'EXECUTED', 'command.ops', NOW() - INTERVAL '2 hours', NOW() - INTERVAL '2 hours'),
  ('SpaceVE-1A', 512, 1, 'CAMERA_ON',     '1a00c0000001 02fd', 2, 'EXECUTED', 'payload.ops', NOW() - INTERVAL '1 hour',  NOW() - INTERVAL '58 minutes'),
  ('SpaceVE-1B', 513, 0, 'NOP',           '1a01c0000001 00ff', 1, 'EXECUTED', 'command.ops', NOW() - INTERVAL '3 hours', NOW() - INTERVAL '3 hours'),
  ('SpaceVE-1A', 512, 3, 'DOWNLINK_ENABLE','1a00c0000001 06f9', 2, 'PENDING',  'payload.ops', NOW() - INTERVAL '5 minutes', NULL)
ON CONFLICT DO NOTHING;

GRANT ALL ON ALL TABLES IN SCHEMA public TO spaceops;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO spaceops;
