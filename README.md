# AI SOC Analyst Agent

結合 **ML 告警分級**、**MITRE ATT&CK 領域知識** 與 **LLM 推理** 的資安維運中心（SOC）智慧代理人。
Agent 針對資安事件提供 TP / BP / FP 分級、ATT&CK 攻擊鏈對應與處置建議，每個結論都附上證據；信心不足、結論衝突、高風險或證據不足時，主動交由分析師複核。

> AIOT 課程期末專題 — 目前為 **Proposal 階段**。

## 專題文件

| 文件 | 內容 |
|---|---|
| [`docs/proposal.md`](docs/proposal.md) | Proposal：Abstract、Introduction、Related Work、Deep Research、Proposed Scheme、References |
| [`docs/AI_SOC_Analyst_Agent-Proposal.pdf`](docs/AI_SOC_Analyst_Agent-Proposal.pdf)（[PPTX](docs/AI_SOC_Analyst_Agent-Proposal.pptx)） | Proposal 簡報 |
| [`DESIGN.md`](DESIGN.md) | 系統設計：Architecture、Components、Data、Algorithm、Evaluation Plan |
| [`data/README.md`](data/README.md) | 資料集來源與下載方式 |

## 系統概觀

```
① 分析師 / 告警佇列 → ② 事件輸入 → ③ Planner & Reasoning Agent
   ↔ ④ 證據取得（事件資料、Log 查詢）
   ↔ ⑤ 分析引擎（分級模型、SHAP、相似事件）
   ↔ ⑥ 領域知識（MITRE ATT&CK、NIST SP 800-61 Rev. 3、D3FEND）
→ ⑦ 決策融合與升級判斷 → ⑧ 事件報告 / Dashboard
```

完整架構圖、流程圖與 Pseudocode 見 [`DESIGN.md`](DESIGN.md)。

## 資料集

- **Microsoft GUIDE** — 真實 SOC 事件與分析師分級標籤（主資料集）
- **ExCyTIn-Bench** — LLM Agent 資安調查能力 benchmark
- **MITRE ATT&CK** — 領域知識庫

## 目錄結構

```
.
├── README.md
├── DESIGN.md                     # 系統設計文件
├── docs/
│   ├── proposal.md               # Proposal 文件
│   └── AI_SOC_Analyst_Agent-Proposal.pptx / .pdf   # Proposal 簡報
├── data/
│   └── README.md                 # 資料下載與放置方式（資料檔本身不納入版本控制）
├── experiments/
│   ├── e0_profile_guide.py       # GUIDE 資料檢查腳本
│   └── results/                  # 實驗輸出
└── src/soc_agent/                # Agent 原始碼（實作階段）
```

## Installation

完整安裝方式於實作階段補上。目前的資料檢查腳本只需要 Python 3 與 pandas：

```bash
pip install pandas
```

## How to Run

Agent 本體於實作階段補上。目前可以重現 GUIDE 訓練集的資料檢查（需先依 [`data/README.md`](data/README.md) 下載資料）：

```bash
python experiments/e0_profile_guide.py data/archive/GUIDE_Train.csv > experiments/results/guide_train_profile.json
```

輸出包含列數、事件數、標籤分布與各欄位的缺值比例，結果摘要見 [`DESIGN.md`](DESIGN.md) §5。

## Demo

實作階段補上。

## 組員

第 16 組

| 姓名 |
|---|
| 蘇恩平 |
| 周妤 |
| 袁靖淇 |
| 蕭宥瑄 |
