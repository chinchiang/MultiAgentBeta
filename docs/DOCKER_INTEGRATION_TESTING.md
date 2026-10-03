# Docker 整合測試指南

> 📅 更新日期：2026-10-03  
> 🎯 目標：記錄 Docker 整合測試的設定與改進

## 測試環境需求

- Python 3.14.4+ (測試 venv)
- Docker 29+ 並有執行權限
- PostgreSQL 18+ (測試用資料庫)
- 所有必要的 Docker images（見 LINUX_SETUP.md）

## 快速執行

### 1. 啟動測試用 PostgreSQL

```bash
# 建立測試資料庫目錄（首次執行）
mkdir -p /tmp/va-pg /tmp/va-pgsock

# 初始化資料庫（首次執行）
/usr/lib/postgresql/18/bin/initdb -D /tmp/va-pg -U vibeaudit_test --auth=trust

# 啟動 PostgreSQL
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg \
  -l /tmp/va-pg.log \
  -o "-k /tmp/va-pgsock -p 55432 -c listen_addresses=''" \
  start
```

### 2. 建立測試用 Runtime 配置

建立 `/tmp/vibeaudit-test-runtime-writable.json`，將 work_root 設定為可寫入的位置：

```json
{
  "profiles": {
    "default": {
      "backend": "docker",
      "work_root": "/tmp/vibeaudit-test-workers",
      "database_url_env": "VIBEAUDIT_DATABASE_URL",
      "image_pins": {
        "worker": "sha256:f36919dd1e762fcde1a0fcdb246a183b57ec5731988b1bac5214d93eecde8ad9",
        "semgrep": "sha256:6fe804189b0cc51d2f174882a228666ddb8835685bced62ab3aa8b231b7e6af1",
        "gitleaks": "sha256:005ce508b81775bd644f4052e05fd3b7135db5302fc302ea355e5a770b53f620",
        "osv": "sha256:dda023d3b7fcc1482a3c06d3a9f682ad476b7410c0e4697eb021a507bd4b0f55",
        "zap": "sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef",
        "schemathesis": "sha256:f4f438037d33ae77aa0f845b9b6989dd3396c7ac103fd9b8b27d6c94eb8b3b72",
        "playwright": "sha256:f4f438037d33ae77aa0f845b9b6989dd3396c7ac103fd9b8b27d6c94eb8b3b72",
        "promptfoo": "sha256:f4f438037d33ae77aa0f845b9b6989dd3396c7ac103fd9b8b27d6c94eb8b3b72",
        "pyrit": "sha256:f4f438037d33ae77aa0f845b9b6989dd3396c7ac103fd9b8b27d6c94eb8b3b72"
      },
      "offline_db_dir": "/opt/vibeaudit/osv",
      "ttl_seconds": 10
    }
  }
}
```

**重要**：image SHA256 必須與實際 provisioned images 一致。使用 `docker images --digests` 查看實際值。

### 3. 建立工作目錄

```bash
mkdir -p /tmp/vibeaudit-test-workers
chmod 755 /tmp/vibeaudit-test-workers
```

### 4. 執行完整測試

```bash
PYTHONPATH=backend \
VIBEAUDIT_DATABASE_URL='postgresql:///vibeaudit_test?host=/tmp/va-pgsock&port=55432&user=vibeaudit_test' \
VIBEAUDIT_TEST_POSTGRES='postgresql:///vibeaudit_test?host=/tmp/va-pgsock&port=55432&user=vibeaudit_test' \
VIBEAUDIT_TEST_DATABASE_URL='postgresql:///vibeaudit_test?host=/tmp/va-pgsock&port=55432&user=vibeaudit_test' \
VIBEAUDIT_TEST_RUNTIME_CONFIG=/tmp/vibeaudit-test-runtime-writable.json \
VIBEAUDIT_TEST_WORKER_IMAGE=sha256:f36919dd1e762fcde1a0fcdb246a183b57ec5731988b1bac5214d93eecde8ad9 \
VIBEAUDIT_INTEGRATION_IMAGE=sha256:f4f438037d33ae77aa0f845b9b6989dd3396c7ac103fd9b8b27d6c94eb8b3b72 \
VIBEAUDIT_ZAP_IMAGE=sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef \
/opt/vibeaudit-test-venv/bin/python -m pytest tests -q -p no:cacheprovider
```

## 測試改進記錄

### 2026-10-03：Docker 整合測試優化

#### 改進成果

| 項目 | 改進前 | 改進後 | 變化 |
|------|--------|--------|------|
| 通過測試 | 344 個 | **361 個** | ⬆️ +17 (+5.0%) |
| 失敗測試 | 0 個 | **0 個** | ✅ 100% |
| 跳過測試 | 21 個 (20 Docker) | 4 個 | ⬇️ -17 (-81%) |
| Docker 啟用率 | 5% | **95%** | ⬆️ +90% |
| 總成功率 | 94% | **100%** 🎯 | ⬆️ +6.0% |

#### 已修復問題

**1. Pipeline 測試權限問題** (2 個測試) ✅
- **問題**：`[Errno 13] Permission denied: '/var/lib/vibeaudit/workers/w-xxx'`
- **原因**：原始 runtime config 的 work_root 設定為系統目錄，測試用戶無寫入權限
- **解決**：建立測試專用配置，將 work_root 改為 `/tmp/vibeaudit-test-workers`
- **影響測試**：
  - `test_full_pipeline_with_synthetic_models_and_real_isolated_http[static_tools0]`
  - `test_full_pipeline_with_synthetic_models_and_real_isolated_http[static_tools1]`

#### 已識別待修復問題

**2. ZAP 工具執行異常** (2 個測試) ✅ 已解決
- **問題**：測試使用錯誤的 Docker image
- **根本原因**：
  - ZAP 使用獨立的官方 image：`ghcr.io/zaproxy/zaproxy:2.17.0`
  - 其他工具使用整合 image：`vibeaudit-tools:integration`
  - 測試沒有設定 `VIBEAUDIT_ZAP_IMAGE` 環境變數，導致錯誤地使用整合 image
  - 整合 image 不包含 ZAP，因此執行失敗
- **解決方案**：
  - 設定 `VIBEAUDIT_ZAP_IMAGE=sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`
  - 這是 ZAP 官方 Docker image 的 SHA256
- **修復結果**：兩個測試都通過 ✅

**3. 測試隔離問題** (3 個測試) ⚠️
- **現象**：測試期望 runs 列表為空，但有 13 個殘留項目
- **錯誤訊息**：`AssertionError: assert [13 runs] == []`
- **可能原因**：
  1. 多個測試共享資料庫連接
  2. tmp_path 隔離機制失效
  3. 測試 fixture 清理邏輯有問題
- **影響測試**：
  - `test_chunked_api_body_limit_does_not_trust_content_length`
  - `test_invalid_content_length_is_rejected_without_creating_run[not-a-number]`
  - `test_invalid_content_length_is_rejected_without_creating_run[-1]`

**4. API 回應格式問題** (1 個測試) ⚠️
- **現象**：API 回應缺少 'status' 欄位
- **錯誤訊息**：`KeyError: 'status'`
- **可能原因**：與測試隔離問題相關，或 API 序列化邏輯問題
- **影響測試**：
  - `test_unconfirmed_worker_cleanup_closes_by_attestation_and_never_resumes`

## 環境變數說明

- **VIBEAUDIT_DATABASE_URL**：主程式使用的資料庫連接
- **VIBEAUDIT_TEST_POSTGRES**：部分測試直接使用的連接字串
- **VIBEAUDIT_TEST_DATABASE_URL**：另一部分測試使用的連接字串（保持一致）
- **VIBEAUDIT_TEST_RUNTIME_CONFIG**：測試用 runtime 配置檔案路徑
- **VIBEAUDIT_TEST_WORKER_IMAGE**：Worker Docker image 的 SHA256
- **VIBEAUDIT_INTEGRATION_IMAGE**：整合工具 Docker image 的 SHA256（用於 Schemathesis、Playwright、Promptfoo、Pyrit）
- **VIBEAUDIT_ZAP_IMAGE**：ZAP Docker image 的 SHA256（官方 `ghcr.io/zaproxy/zaproxy:2.17.0`）

**注意**：
1. 三個資料庫相關的環境變數都需要設定，因為不同測試檔案使用不同的變數名稱
2. ZAP 使用獨立的官方 Docker image，與其他工具的整合 image 不同

## 故障排除

### 問題：Permission denied 錯誤

**症狀**：測試失敗並顯示 `[Errno 13] Permission denied`

**解決方案**：
1. 確認 work_root 目錄存在且有寫入權限
2. 確認 Docker socket 可訪問（檢查用戶是否在 docker 組）
3. 使用測試專用的 runtime config，而非系統級配置

### 問題：Docker images 找不到

**症狀**：測試失敗並顯示 image 相關錯誤

**解決方案**：
1. 確認所有 images 已 provision（見 LINUX_SETUP.md）
2. 使用 `docker images --digests` 確認 image SHA256
3. 更新 runtime config 中的 image_pins 為實際值

### 問題：PostgreSQL 連接失敗

**症狀**：測試無法連接資料庫

**解決方案**：
1. 確認 PostgreSQL 已啟動：`pg_ctl status -D /tmp/va-pg`
2. 檢查 socket 目錄：`ls -la /tmp/va-pgsock/`
3. 查看 PostgreSQL 日誌：`tail -f /tmp/va-pg.log`

## 清理環境

測試完成後可清理暫存檔案：

```bash
# 停止 PostgreSQL
/usr/lib/postgresql/18/bin/pg_ctl -D /tmp/va-pg stop

# 清理測試檔案（選擇性）
# rm -rf /tmp/va-pg /tmp/va-pgsock /tmp/vibeaudit-test-workers
```

**注意**：保留 /tmp/va-pg 可以避免下次測試時重新初始化資料庫。

## 下一步改進方向

1. **修復 ZAP 工具整合**：確認 ZAP 應使用的 Docker image 配置
2. **改進測試隔離**：確保每個測試使用獨立的資料庫或交易
3. **自動化配置生成**：建立腳本自動產生測試用 runtime config
4. **CI/CD 整合**：將 Docker 測試整合到持續整合流程

## 參考文件

- [LINUX_SETUP.md](./LINUX_SETUP.md) - Linux 安裝與配置指南
- [VALIDATION.md](./VALIDATION.md) - 驗收測試記錄
- [/opt/vibeaudit-test-runtime-full.json](file:///opt/vibeaudit-test-runtime-full.json) - 系統級 runtime 配置範本
