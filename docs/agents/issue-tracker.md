# Issue tracker：GitHub

本專案的工作項目與規格存放於 chinchiang/MultiAgentBeta 的
GitHub Issues，使用 gh CLI 操作。

## 操作規則

- 每次操作明確指定 `--repo chinchiang/MultiAgentBeta`。
- 讀取：`gh issue view <number> --repo chinchiang/MultiAgentBeta --json number,title,body,labels,comments`
- 列出：`gh issue list --repo chinchiang/MultiAgentBeta --state open`
- 建立：`gh issue create --repo chinchiang/MultiAgentBeta --title "<title>" --body-file <file>`
- 留言：`gh issue comment <number> --repo chinchiang/MultiAgentBeta --body-file <file>`
- 更新標籤：`gh issue edit <number> --repo chinchiang/MultiAgentBeta --add-label "<label>"`
- 移除標籤：同上，改用 `--remove-label "<label>"`。
- 關閉前先留言說明，再執行 `gh issue close <number> --repo chinchiang/MultiAgentBeta`。
- 多行內容先寫入檔案，再使用 `--body-file`。
- 發布至 issue tracker 表示建立 GitHub issue；取得 ticket 表示讀取對應 issue。
- 父子工作項目優先使用原生 sub-issues；不支援時，在子項目本文記錄 `Part of #<parent>`。
- 阻擋關係優先使用原生 dependencies；不支援時記錄 `Blocked by: #<number>`。
  所有阻擋項目關閉後，工作才可開始。
- Wayfinder 使用一張標記 `wayfinder:map` 的 issue 保存地圖；
  子項目記錄於地圖，依順序挑選無阻擋且無負責人的項目。

## PR 設定

**PRs as a request surface: no.**

---
# Issue tracker: GitHub

Tickets and specifications live in GitHub Issues in
chinchiang/MultiAgentBeta. Use the gh CLI.

## Operations

- Explicitly pass `--repo chinchiang/MultiAgentBeta`.
- Read: `gh issue view <number> --repo chinchiang/MultiAgentBeta --json number,title,body,labels,comments`
- List: `gh issue list --repo chinchiang/MultiAgentBeta --state open`
- Create: `gh issue create --repo chinchiang/MultiAgentBeta --title "<title>" --body-file <file>`
- Comment: `gh issue comment <number> --repo chinchiang/MultiAgentBeta --body-file <file>`
- Label: `gh issue edit <number> --repo chinchiang/MultiAgentBeta --add-label "<label>"`
- Remove labels with `--remove-label "<label>"`.
- Comment with the reason before running `gh issue close <number> --repo chinchiang/MultiAgentBeta`.
- Write multiline content to a file and pass `--body-file`.
- Publishing to the tracker means creating an issue; fetching a ticket means reading it.
- Prefer native sub-issues; otherwise record `Part of #<parent>` in the child.
- Prefer native dependencies; otherwise record `Blocked by: #<number>`.
  Start work only after every blocker is closed.
- Wayfinder stores its map in an issue labelled `wayfinder:map`;
  list children there and select the first unblocked, unassigned ticket.

## PR configuration

**PRs as a request surface: no.**
