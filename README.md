# PCAPNG Audit Service

统一审计不同采集器生成的 PCAPNG 文件：规范化各接口的时间精度（`if_tsresol`）
与偏移（`if_tsoffset`），消除节字节序差异，按捕获顺序检测报文倒序。

零第三方运行时依赖，仅使用 Python 3.11 标准库。

## API

### `POST /api/pcapng/audit?maxBackwardNanoseconds=<非负整数>`

- `Content-Type: application/x-pcapng`
- 请求体：原始 PCAPNG，**最大 8 MiB**
- `maxBackwardNanoseconds`：允许的相邻报文非负回退量（纳秒）

校验规则（任一不满足返回 `400`）：

- 1～8 个 Section；每节以 SHB 开始，其后仅允许 IDB 与 EPB；
- 块首尾 Block Total Length 一致、4 字节对齐且不越界；
- 报文与选项的 4 字节填充存在且为零，选项边界合法；
- 每节按 SHB Byte-Order Magic 确定节内字节序（小端/大端均支持）；
- EPB 的 Interface ID 必须引用本节已定义的 IDB；
- `captured packet length ≤ original packet length` 且 `≤ if_snaplen`
  （snaplen 为 0 时不限）；
- `if_tsresol` 非零；`if_tsoffset` 为有符号 64 位整数。

时间戳换算：默认精度为十进制微秒（res=6）。先在精度单位上加上
`if_tsoffset`，再换算为纳秒；无法整除时采用**最近偶数舍入（banker's
rounding / round-half-to-even）**，二进制精度（MSB=1，分母 2^n）同样适用。

成功响应（`200`）：

```json
{
  "packets": [
    {
      "section": 0,
      "interface": 1,
      "timestampNanoseconds": 2000000000,
      "capturedLength": 64,
      "originalLength": 128,
      "sha256": "…"
    }
  ],
  "violation": null
}
```

当相邻报文（捕获顺序上的前一个 → 当前）的规范纳秒时间回退量
**严格大于** `maxBackwardNanoseconds` 时，`violation` 标出**最早**的违规
报文及实际回退量：

```json
{
  "index": 7,
  "section": 1,
  "interface": 0,
  "timestampNanoseconds": 3999999000,
  "backwardNanoseconds": 1000
}
```

`GET /healthz` 返回 `200 {"status":"ok"}`，供容器健康检查使用。

## 本地运行与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q
PORT=8080 python -m app.server
python scripts/smoke_test.py http://127.0.0.1:8080
```

## Docker Compose

```bash
HOST_PORT=9090 docker compose up -d --build web      # 可配置宿主端口
docker compose up --build verify                     # 一次性验证服务
```

- `web`：常驻审计服务，带 `/healthz` 健康检查；宿主端口由 `HOST_PORT`
  （默认 8080）配置，亦可复制 `.env.example` 为 `.env`。
- `verify`：一次性服务，`depends_on: web: service_healthy`，在依赖健康后
  依次执行单元测试、字节码构建、含混合字节序样本的 API 冒烟，并以容器
  退出码报告结果（0 成功）。
