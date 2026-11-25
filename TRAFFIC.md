# 逐网卡流量计量

通过 `--traffic-config <file>` 或 `MONITOR_TRAFFIC_CONFIG` 启用持久流量计量。两者同时设置时命令行优先。未设置时使用原生无状态采集。

## 选择网卡和配置倍率

继续用 `--iface` 或 `MONITOR_IFACE` 选择接口。正向名单使用完整网卡名，`-name` 优先排除。没有正向名单时沿用原生拓扑去重。扩展配置接受 1–15 字节的 ASCII 字母、数字、点、下划线和连字符，首字符不能为连字符，单独的 `.` 和 `..` 也不允许。

[倍率示例](examples/traffic-weighted.json)假设 `--iface uplink0,relay0`，两者均为占位名称。示例的入站增量为 `uplink0_RX`，出站增量为 `uplink0_TX + relay0_RX + 2 × relay0_TX`，其中各项均指本次可比较的采样增量。

| 配置项 | 含义 |
|---|---|
| `state_file` | 持久状态文件的绝对路径，文件名的 `.lock` 和 `.tmp` 后缀保留给内部使用 |
| `report` | `raw`（默认）上报原始累计，`billing` 上报加权累计 |
| `strict` | 默认 `true`。正向名单中未被排除的接口缺失时暂停上报。设为 `false` 时，其他选中接口继续计量 |
| `checkpoint_secs` | 落盘间隔，默认 30 秒，范围 5–3600 秒 |
| `weights` | 以网卡名为键，为已选中的网卡指定权重 |

每个专属权重必须提供以下四项。未指定权重的网卡使用表中的默认值。[原始累计示例](examples/traffic-raw.json)沿用这些默认值。

| 字段 | 含义 | 默认值 |
|---|---|---:|
| `rx_to_in_ppm` | 将 RX 映射到加权入站 | 1000000 |
| `rx_to_out_ppm` | 将 RX 映射到加权出站 | 0 |
| `tx_to_in_ppm` | 将 TX 映射到加权入站 | 0 |
| `tx_to_out_ppm` | 将 TX 映射到加权出站 | 1000000 |

权重为整数 ppm，0 表示忽略，500000 表示 0.5 倍，1000000 表示 1 倍，最大值为 4294967295。每张网卡分别应用两个方向的公式，每个方向以百万分之一字节为单位结转余数。新建的 schema 2 账本按网卡名保存余数。已有的 schema 1 账本继续按原格式汇总所有网卡的加权增量，再按入站和出站分别结转共享余数。配置在启动时读取，修改配置后需重启，已计量的增量和初始累计保持原值。

## 本地诊断和初始化

```sh
monitor-agent --traffic-config ./traffic.json --iface uplink0,relay0 --traffic-check
monitor-agent --traffic-config ./traffic.json --traffic-init ./seed.json
monitor-agent --traffic-config ./traffic.json --traffic-status
```

- `--traffic-check` 输出 JSON，包括原生筛选参数、选中接口的内核计数器和身份、`sample.native_epoch`、缺失名单和未使用的权重。启用严格模式且名单缺卡时输出 `valid: false`，退出码非零。省略配置也可检查原生筛选结果。
- `--traffic-init` 从 [seed 文件](examples/traffic-seed.json)显式创建状态。它取得独占锁，目标状态已存在时退出。
- `--traffic-status` 输出最后写入的状态和 `report_totals`，包括 `raw`、`billing`、共享 `remainder` 或逐卡 `remainders`、接口基线、重置次数和检查点。诊断只读取状态文件，运行中的检查点可以同时更新。检查和状态命令均无需 hub 地址或 token，也不会创建锁或状态目录。

新节点可使用零累计，`boot_id` 可取自检查输出的 `sample.native_epoch`。从无状态采集首次切换到账本时，先停用原 Agent，从最后一条已上报的原生 `report` 复制完整的 `boot_id`、`net_rx_total`、`net_tx_total`，在 `note` 记录来源。用这三个原生字段初始化。面板汇总、账期用量和诊断命令的当前内核累计都不能充当这三个字段。新账本的首次采样只建立基线，之前的累计按播种值保留。

初始化后，使用包含流量扩展的 Agent 启动。沿用同一份配置和网卡筛选参数。

```sh
monitor-agent --traffic-config ./traffic.json --iface uplink0,relay0 \
  --server https://hub.example.com --token '<node token>'
```

状态目录需由 Agent 用户控制，典型权限为 0700，状态与锁文件的典型权限为 0600。每次检查点将临时文件同步后原子替换状态，再同步父目录。运行中的 Agent 独占对应账本。状态缺失、损坏、格式不兼容或上报口径改变时，启动会失败。切换 `raw` 和 `billing` 时需使用新的状态路径及相应的初始化流程。

## 接续 schema 1 账本

停用旧 Agent 后，保留同一状态文件、`--iface`、权重和上报口径，直接启动新版。可先用 `--traffic-status` 核对最新检查点，用同一运行环境中的 `--traffic-check` 核对内核 boot ID、网络命名空间、纳入计量的接口集合、每个接口的身份、权重和双向计数。能确认接口未重置且两方向的计数都可与检查点比较时，新版从检查点继续计量，保留原始累计、计费累计、共享余数和原上报 epoch。首次采样没有上一个进程的单调时钟读数，实时速率从下一次采样开始计算。

无法确认同一内核启动、同一网络命名空间、接口连续性或计数可比性时，先暂停要求无损的切换。采样错误、接口重建或计数器重置都可能留下无法补计的区间。回退到清除启动基线的旧版时，停止新版并使用最新的 schema 1 检查点，确认检查点到旧版首次采样之间没有待计增量。恢复较早的副本可能回退已上报累计。

## 上报与连续性

`hello` 和 `report` 沿用原生 JSON-RPC 和字段。启用计量时，`net_rx` / `net_tx` 仍为采样得到的原始字节每秒，`net_rx_total` / `net_tx_total` 来自当前上报模式的已落盘累计，`boot_id` 固定为播种的原生 epoch。`iface` 仍为 Agent 使用的原生筛选字符串。面板根据累计差值计算的历史数据随所选上报口径变化。

开启计量后，Agent 按 `--interval` 独立采样，与 hub 断开期间仍记录增量。累计在各检查点更新，上报会再等待下一个发送周期。若检查点写入失败，Agent 保留已采样的内存增量，待成功落盘后再恢复上报。schema 2 重启时保留已落盘累计和余数，首次采样重新建立计数器基线。schema 1 从可比较的持久基线续计。

接口由名称、ifindex、iflink、MAC 和链路类型识别。系统或网络命名空间改变、接口重新出现或身份更改时，为受影响的接口重建基线。单方向计数器倒退时跳过该方向的增量，另一方向照常统计。采样错误会暂停上报并清除无法确认的计数器基线。若两次采样之间接口被原样重建且计数器更大，仅凭这些字段无法辨认此次替换。
