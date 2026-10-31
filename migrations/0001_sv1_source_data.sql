-- 0001: dữ liệu nguồn của SV1 (DatasetSnapshot lưu thành các bảng).
-- Đề xuất của SV1, cần người điều phối duyệt (ARCHITECTURE.md, mục 2 và 4).
-- Mỗi snapshot bất biến: một dataset_id gắn với một nội dung (content_sha256).
-- Cột row_order giữ nguyên thứ tự bản ghi trong snapshot để đọc lại đúng từng phần tử.
-- Thời điểm lưu dạng UTC. Danh sách evidence lưu thành chuỗi JSON.

CREATE TABLE datasets (
    dataset_id     TEXT PRIMARY KEY,
    schema_version TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    source         TEXT NOT NULL CHECK (source IN ('synthetic', 'scanner', 'manual', 'mixed')),
    content_sha256 TEXT NOT NULL,
    recorded_at    TIMESTAMPTZ NOT NULL
);

CREATE TABLE assets (
    dataset_id      TEXT NOT NULL REFERENCES datasets (dataset_id),
    row_order       INTEGER NOT NULL,
    asset_id        TEXT NOT NULL,
    name            TEXT NOT NULL,
    asset_type      TEXT,
    internet_facing BOOLEAN,
    criticality     INTEGER CHECK (criticality IS NULL OR criticality BETWEEN 1 AND 5),
    sensitive_data  BOOLEAN,
    PRIMARY KEY (dataset_id, asset_id)
);

CREATE TABLE services (
    dataset_id      TEXT NOT NULL REFERENCES datasets (dataset_id),
    row_order       INTEGER NOT NULL,
    service_id      TEXT NOT NULL,
    asset_id        TEXT NOT NULL,
    protocol        TEXT NOT NULL CHECK (protocol IN ('tcp', 'udp')),
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    product         TEXT,
    product_version TEXT,
    PRIMARY KEY (dataset_id, service_id),
    FOREIGN KEY (dataset_id, asset_id) REFERENCES assets (dataset_id, asset_id)
);

CREATE TABLE findings (
    dataset_id       TEXT NOT NULL REFERENCES datasets (dataset_id),
    row_order        INTEGER NOT NULL,
    finding_id       TEXT NOT NULL,
    asset_id         TEXT NOT NULL,
    service_id       TEXT,
    vulnerability_id TEXT NOT NULL,
    cvss_score       DOUBLE PRECISION
        CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    epss_probability DOUBLE PRECISION
        CHECK (epss_probability IS NULL OR (epss_probability >= 0 AND epss_probability <= 1)),
    is_kev           BOOLEAN,
    source           TEXT NOT NULL CHECK (source IN ('synthetic', 'scanner', 'manual')),
    evidence         TEXT NOT NULL,
    observed_at      TIMESTAMPTZ,
    enriched_at      TIMESTAMPTZ,
    PRIMARY KEY (dataset_id, finding_id),
    FOREIGN KEY (dataset_id, asset_id) REFERENCES assets (dataset_id, asset_id),
    FOREIGN KEY (dataset_id, service_id) REFERENCES services (dataset_id, service_id)
);

CREATE INDEX findings_by_asset ON findings (dataset_id, asset_id);

CREATE INDEX findings_by_vulnerability ON findings (dataset_id, vulnerability_id);

CREATE TABLE connections (
    dataset_id        TEXT NOT NULL REFERENCES datasets (dataset_id),
    row_order         INTEGER NOT NULL,
    connection_id     TEXT NOT NULL,
    source_asset_id   TEXT NOT NULL,
    target_asset_id   TEXT NOT NULL,
    target_service_id TEXT,
    allowed           BOOLEAN NOT NULL,
    evidence          TEXT NOT NULL,
    PRIMARY KEY (dataset_id, connection_id),
    FOREIGN KEY (dataset_id, target_asset_id) REFERENCES assets (dataset_id, asset_id),
    FOREIGN KEY (dataset_id, target_service_id) REFERENCES services (dataset_id, service_id)
);

CREATE TABLE exploit_rules (
    dataset_id          TEXT NOT NULL REFERENCES datasets (dataset_id),
    row_order           INTEGER NOT NULL,
    rule_id             TEXT NOT NULL,
    source_asset_id     TEXT NOT NULL,
    target_asset_id     TEXT NOT NULL,
    required_finding_id TEXT,
    required_state      TEXT NOT NULL,
    resulting_state     TEXT NOT NULL,
    rule_type           TEXT NOT NULL CHECK (rule_type IN ('exploit', 'trust')),
    evidence            TEXT NOT NULL,
    PRIMARY KEY (dataset_id, rule_id),
    FOREIGN KEY (dataset_id, target_asset_id) REFERENCES assets (dataset_id, asset_id),
    FOREIGN KEY (dataset_id, required_finding_id) REFERENCES findings (dataset_id, finding_id)
);
