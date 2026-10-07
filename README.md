# PCAPNG Audit Platform

统一审计不同采集器生成的 PCAPNG 文件：规范化接口时间精度/偏移与各节字节序，
按捕获顺序输出报文时间与 SHA-256，并标出超出阈值的时间回退。

## 接口

### `POST /api/pcapng/audit?maxBackwardNanoseconds=<非负整数>`

- 请求体：不超过 **8 MiB**，`Content-Type: application/x-pcapng`
- 查询参数 `maxBackwardNanoseconds`：允许的非负回退量（纳秒），必填
- 成功返回 `200`：

```json
{
  "sectionCount": 1,
  "packetCount": 2,
  "maxBackwardNanoseconds": 500,
  "packets": [
    {
      "section": 1,
      "interface": 0,
      "timestampNs": 1000,
      "packetLength": 1514,
      "capturedLength": 1514,
      "sha256": "…"
    }
  ],
  "violation": null
}
```

当相邻报文回退**严格大于**阈值时，`violation` 给出最早违规报文（捕获序号
从 0 开始）与实际回退量：

```json
{
  "index": 3,
  "section": 1,
  "interface": 1,
  "timestampNs": 1599000000,
  "packetLength": 7,
  "sha256": "…",
  "previousTimestampNs": 1600000000,
  "backwardNanoseconds": 1000000
}
```

错误码：`415`（Content-Type 不符）、`413`（超过 8 MiB）、
`422`（文件结构非法或阈值非法）。

### `GET /healthz`

返回 `{"status":"ok"}`，供容器健康检查使用。

## PCAPNG 校验规则

- 文件含 **1–8 个 Section**，每节以 SHB 起始，其后只允许 IDB 与 EPB；
- 每个块的首尾块长度必须一致，总长度为 4 的倍数；
- 报文数据与选项均按 4 字节填充，选项 TLV 边界必须合法
  （`opt_endofopt` 长度须为 0，其后只允许零填充）；
- 每节字节序由 SHB 的 Byte-Order Magic 决定，支持同一文件中混合字节序；
- EPB 的 `interface_id` 必须引用本 SHB 之后已出现的 IDB（每节接口独立编号）；
- 时间戳按对应接口的 `if_tsresol` 解释，缺省为**十进制微秒**（6），
  高位为 1 时为 2 的幂精度；换算纳秒使用**精确有理值的最近偶数舍入**
  （ties to even），再加上有符号 `if_tsoffset`；
- 捕获长度不得超过原始长度，也不得超过接口 `snaplen`（0 表示不限）。

## 本地运行

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080
```

## Docker

```bash
# 宿主机端口可通过 HOST_PORT 配置（默认 8080）
HOST_PORT=9000 docker compose up -d --build api

# 一次性验证服务：等待 api 健康后运行测试、构建 wheel、混合字节序冒烟
docker compose up --build verify
# 用退出码报告结果：
docker compose up --build verify; echo "exit=$?"
```

`verify` 服务通过 `depends_on: condition: service_healthy` 在依赖健康后
才启动，依次执行 `scripts/verify.sh` 中的测试、构建与冒烟，任一失败即
以非零退出码结束。

## 本地测试与冒烟

```bash
pytest
python scripts/smoke.py                 # 需要先启动服务，可用 BASE_URL 指定
BASE_URL=http://127.0.0.1:8080 python scripts/smoke.py
```

## 目录结构

```
app/            FastAPI 应用与严格 PCAPNG 解析/审计
testing/        测试与冒烟共用的 PCAPNG 样本构造器（含混合字节序样本）
tests/          解析器与 HTTP 接口测试
scripts/        verify.sh 编排脚本与 smoke.py 实时冒烟
Dockerfile      单镜像支持 api 长驻服务与 verify 一次性任务
docker-compose.yml
```
