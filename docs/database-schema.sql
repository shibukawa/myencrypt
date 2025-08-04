-- MyEncrypt SQLite Database Schema

-- アカウント管理
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,                    -- アカウントID (UUID)
    public_key_jwk TEXT NOT NULL,          -- JWK形式の公開鍵
    contact TEXT,                          -- 連絡先 (JSON配列)
    status TEXT DEFAULT 'valid',           -- valid, deactivated
    terms_agreed BOOLEAN DEFAULT FALSE,    -- 利用規約同意
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 証明書注文
CREATE TABLE orders (
    id TEXT PRIMARY KEY,                    -- 注文ID (UUID)
    account_id TEXT NOT NULL,              -- アカウントID
    status TEXT DEFAULT 'pending',         -- pending, ready, processing, valid, invalid
    domains TEXT NOT NULL,                 -- ドメインリスト (JSON配列)
    not_before DATETIME,                   -- 有効開始日時
    not_after DATETIME,                    -- 有効終了日時
    expires_at DATETIME NOT NULL,          -- 注文有効期限
    certificate_url TEXT,                  -- 証明書URL
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- 発行済み証明書
CREATE TABLE certificates (
    id TEXT PRIMARY KEY,                    -- 証明書ID (UUID)
    order_id TEXT NOT NULL,                -- 注文ID
    account_id TEXT NOT NULL,              -- アカウントID
    serial_number TEXT UNIQUE NOT NULL,    -- 証明書シリアル番号
    domains TEXT NOT NULL,                 -- ドメインリスト (JSON配列)
    certificate_pem TEXT NOT NULL,         -- 証明書 (PEM形式)
    certificate_chain_pem TEXT,            -- 証明書チェーン (PEM形式)
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    status TEXT DEFAULT 'valid',           -- valid, revoked, expired
    revoked_at DATETIME,                   -- 失効日時
    revocation_reason INTEGER,             -- 失効理由コード
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

-- ドメイン認証
CREATE TABLE authorizations (
    id TEXT PRIMARY KEY,                    -- 認証ID (UUID)
    order_id TEXT NOT NULL,                -- 注文ID
    domain TEXT NOT NULL,                  -- ドメイン名
    status TEXT DEFAULT 'pending',         -- pending, valid, invalid, deactivated, expired
    expires_at DATETIME NOT NULL,          -- 認証有効期限
    wildcard BOOLEAN DEFAULT FALSE,        -- ワイルドカード証明書か
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE
);

-- チャレンジ
CREATE TABLE challenges (
    id TEXT PRIMARY KEY,                    -- チャレンジID (UUID)
    authorization_id TEXT NOT NULL,        -- 認証ID
    type TEXT NOT NULL,                    -- http-01, dns-01, tls-alpn-01
    status TEXT DEFAULT 'pending',         -- pending, processing, valid, invalid
    token TEXT NOT NULL,                   -- チャレンジトークン
    key_authorization TEXT,                -- キー認証
    validated_at DATETIME,                 -- 検証完了日時
    error_detail TEXT,                     -- エラー詳細 (JSON)
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (authorization_id) REFERENCES authorizations(id) ON DELETE CASCADE
);

-- Nonce管理
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,                -- Nonce値
    expires_at DATETIME NOT NULL,          -- 有効期限
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 統計情報
CREATE TABLE statistics (
    date DATE PRIMARY KEY,                 -- 日付
    accounts_created INTEGER DEFAULT 0,    -- 作成されたアカウント数
    certificates_issued INTEGER DEFAULT 0, -- 発行された証明書数
    challenges_completed INTEGER DEFAULT 0, -- 完了したチャレンジ数
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- インデックス作成
CREATE INDEX idx_accounts_status ON accounts(status);
CREATE INDEX idx_accounts_created_at ON accounts(created_at);

CREATE INDEX idx_orders_account_id ON orders(account_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_expires_at ON orders(expires_at);

CREATE INDEX idx_certificates_account_id ON certificates(account_id);
CREATE INDEX idx_certificates_serial_number ON certificates(serial_number);
CREATE INDEX idx_certificates_expires_at ON certificates(expires_at);
CREATE INDEX idx_certificates_status ON certificates(status);
CREATE INDEX idx_certificates_domains ON certificates(domains);

CREATE INDEX idx_authorizations_order_id ON authorizations(order_id);
CREATE INDEX idx_authorizations_domain ON authorizations(domain);
CREATE INDEX idx_authorizations_expires_at ON authorizations(expires_at);

CREATE INDEX idx_challenges_authorization_id ON challenges(authorization_id);
CREATE INDEX idx_challenges_type ON challenges(type);
CREATE INDEX idx_challenges_status ON challenges(status);

CREATE INDEX idx_nonces_expires_at ON nonces(expires_at);

-- トリガー: updated_at自動更新
CREATE TRIGGER update_accounts_updated_at 
    AFTER UPDATE ON accounts
    BEGIN
        UPDATE accounts SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_orders_updated_at 
    AFTER UPDATE ON orders
    BEGIN
        UPDATE orders SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_authorizations_updated_at 
    AFTER UPDATE ON authorizations
    BEGIN
        UPDATE authorizations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER update_challenges_updated_at 
    AFTER UPDATE ON challenges
    BEGIN
        UPDATE challenges SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

-- ビュー: 証明書とアカウント情報の結合
CREATE VIEW certificate_details AS
SELECT 
    c.id,
    c.serial_number,
    c.domains,
    c.issued_at,
    c.expires_at,
    c.status,
    c.revoked_at,
    a.id as account_id,
    a.contact as account_contact
FROM certificates c
JOIN accounts a ON c.account_id = a.id;

-- ビュー: 期限切れ間近の証明書
CREATE VIEW expiring_certificates AS
SELECT *
FROM certificate_details
WHERE expires_at <= datetime('now', '+7 days')
AND status = 'valid'
ORDER BY expires_at ASC;
