# MyEncrypt Protocol Support

このドキュメントでは、MyEncryptがサポートするプロトコルと機能について説明します。

## ACME (Automatic Certificate Management Environment)

MyEncryptは RFC 8555 に準拠したACMEプロトコルを実装しています。

### サポートされているエンドポイント

| エンドポイント | メソッド | 説明 | 実装状況 |
|---------------|----------|------|----------|
| `/acme/directory` | GET | ACME サービス情報 | ✅ 完了 |
| `/acme/new-nonce` | HEAD/GET | Nonce取得 | ✅ 完了 |
| `/acme/new-account` | POST | アカウント作成 | ✅ 完了 |
| `/acme/account/{id}` | POST | アカウント管理 | ✅ 完了 |
| `/acme/new-order` | POST | 証明書注文 | ✅ 完了 |
| `/acme/order/{id}` | GET/POST | 注文状態確認 | ✅ 完了 |
| `/acme/order/{id}/finalize` | POST | 証明書確定 | ✅ 完了 |
| `/acme/authz/{id}` | GET/POST | 認証状態確認 | ✅ 完了 |
| `/acme/challenge/{id}` | GET/POST | チャレンジ実行 | ✅ 完了 |
| `/acme/cert/{id}` | GET/POST | 証明書取得 | ✅ 完了 |
| `/acme/revoke-cert` | POST | 証明書失効 | ❌ 未実装 |
| `/acme/key-change` | POST | キー変更 | ❌ 未実装 |

### 認証方式 (Challenge Types)

| 認証方式 | 説明 | 実装状況 |
|----------|------|----------|
| HTTP-01 | HTTP経由でのドメイン所有権確認 | ✅ 完了 |
| DNS-01 | DNS TXTレコードでのドメイン所有権確認 | ❌ 未実装 |
| TLS-ALPN-01 | TLS ALPN拡張での確認 | ❌ 未実装 |

## 証明書管理

### 証明書の特徴

- **アルゴリズム**: ECDSA P-256 + SHA-256
- **デフォルト有効期限**: 24時間（設定可能）
- **CA証明書有効期限**: 800日（設定可能）
- **サポートドメイン**: localhost, *.localhost, *.test, *.example, *.invalid

### 証明書拡張

現在のMyEncryptが生成する証明書には以下の拡張が含まれます：

| 拡張 | 説明 | 実装状況 |
|------|------|----------|
| Key Usage | 鍵の用途制限 | ✅ 完了 |
| Extended Key Usage | 拡張鍵用途 | ✅ 完了 |
| Subject Alternative Name | 代替名 | ✅ 完了 |
| Authority Key Identifier | 発行者鍵識別子 | ✅ 完了 |
| CRL Distribution Points | CRL配布ポイント | ⚠️ オプション |
| Authority Information Access | OCSP/CA発行者URI | ⚠️ オプション |

**注意**: CRL/OCSP拡張は実装されていますが、対応するエンドポイントは未実装です。

## 証明書失効 (Certificate Revocation)

### 失効メカニズム

| 方式 | 説明 | 実装状況 |
|------|------|----------|
| CRL (Certificate Revocation List) | 失効証明書リスト | ❌ 未実装 |
| OCSP (Online Certificate Status Protocol) | オンライン証明書状態確認 | ❌ 未実装 |
| OCSP Stapling | サーバー側OCSP応答配信 | ❌ 未実装 |

### 失効情報の伝達

現在のMyEncryptでは、証明書失効情報をクライアントに伝達する仕組みが実装されていません：

1. **証明書にCRL/OCSP URIは含まれる**（オプション設定時）
2. **しかし対応するエンドポイントは未実装**
3. **ACMEクライアントが適切に証明書を管理することを前提**

### 実用上の影響

- **開発環境**: 問題なし（失効チェックは通常不要）
- **ACMEクライアント**: エラーにならない（拡張の欠如は許容される）
- **ブラウザ**: 失効チェックは行われない

## 自動更新

### 更新の仕組み

```
1. クライアントが定期的にMyEncryptサーバーに接続
2. 既存アカウント情報で認証（JWS署名）
3. 証明書の有効期限をチェック
4. 期限が近い場合、新しい証明書を要求
5. ドメイン検証（HTTP-01チャレンジ）
6. 新しい証明書を発行・配布
```

### 必要な情報

**クライアント側で保持:**
- アカウント秘密鍵（署名用）
- アカウントID
- 証明書秘密鍵
- 現在の証明書

**サーバー側で保持:**
- アカウント公開鍵（署名検証用）
- アカウントメタデータ
- 発行済み証明書情報
- 認証履歴（オプション）

**重要**: 秘密鍵は絶対に送信されません。JWS署名により身元確認を行います。

## ACMEクライアント互換性

### テスト済みクライアント

| クライアント | 互換性 | 備考 |
|-------------|--------|------|
| Certbot | ✅ 互換 | Let's Encrypt公式クライアント |
| acme.sh | ✅ 互換 | 軽量シェルスクリプト実装 |
| Traefik | ✅ 互換 | 内蔵ACME機能 |

### 互換性に関する注意点

1. **CRL/OCSP拡張の欠如**: 既存のACMEクライアントはエラーにしません
2. **開発用CA**: mkcertなど他の開発用CAも同様の実装です
3. **RFC準拠**: ACME仕様上、CRL/OCSP拡張は必須ではありません

## 設定オプション

### 証明書関連

```yaml
# config.yaml
individual_cert_ttl: "24h"    # 個別証明書の有効期限
ca_cert_ttl: "800d"           # CA証明書の有効期限
auto_renewal: true            # 自動更新の有効化
renewal_interval: "1h"        # 更新チェック間隔
```

### ネットワーク関連

```yaml
bind_address: "0.0.0.0"       # バインドアドレス
http_port: 14000              # ACME/管理ポート
```

### ドメイン制限

```yaml
allowed_domains:              # 許可ドメイン
  - "localhost"
  - "*.localhost"
  - "*.test"
  - "*.example"
  - "*.invalid"
```

## 今後の実装予定

### 高優先度

1. **DNS-01チャレンジ**: ワイルドカード証明書対応
2. **証明書失効機能**: CRL/OCSPエンドポイント実装
3. **メトリクス**: 証明書発行・更新統計

### 中優先度

1. **TLS-ALPN-01チャレンジ**: 追加認証方式
2. **External Account Binding**: 企業環境対応
3. **レート制限**: DoS攻撃対策

### 低優先度

1. **OCSP Stapling**: パフォーマンス向上
2. **Certificate Transparency**: 透明性ログ対応
3. **HSM対応**: ハードウェアセキュリティモジュール

## 制限事項

### 現在の制限

1. **単一CA**: 複数CA環境は未対応
2. **メモリストレージ**: 再起動で一部データ消失
3. **HTTP-01のみ**: DNS-01チャレンジ未対応
4. **失効チェックなし**: CRL/OCSPエンドポイント未実装

### セキュリティ考慮事項

1. **開発環境専用**: 本番環境での使用は推奨されません
2. **HTTP通信**: ACME通信は平文（開発環境では一般的）
3. **簡易認証**: 本格的なレート制限なし

## 参考資料

- [RFC 8555 - Automatic Certificate Management Environment (ACME)](https://tools.ietf.org/html/rfc8555)
- [RFC 5280 - Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile](https://tools.ietf.org/html/rfc5280)
- [RFC 6960 - X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP](https://tools.ietf.org/html/rfc6960)
- [Let's Encrypt ACME Implementation](https://letsencrypt.org/docs/)
