视频站的防盗链打开之后，盗链站点照样能直接播，反倒是自家页面被拦了：规范化不去查询串，带参数的请求被当成不同路径；规范化不折叠重复斜杠，绕道路径绕过作用域；作用域取根目录，整站共用一个令牌；作用域用纯字符串前缀，同名前缀目录互相命中；令牌不含过期时间，永久有效；过期判定用严格小于，恰好到期仍可用；有效期不校验上限，可签超长令牌；来源判定只用后缀比较，仿冒域名命中；策略校验不检查作用域是否过宽；批量校验复用令牌作用域，后一个请求命中前一个请求的路径。cdn/token.py 是核心，tests/test_token.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```bash
python -m pytest tests -q
```

初始状态应输出 15 failed，且没有 error。测试完全离线运行，不访问网络。

## 字段

| 字段 | 值 |
| --- | --- |
| 方向 | 安全 |
| 类型 | 漏洞检测与攻防 |
| 任务 | Bugfix |
| 运行环境 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

## 约束

- 实现只使用标准库 hmac、hashlib、re、urllib.parse；不联网、不使用随机数，时间一律显式传入。
- tests/test_token.py 与 tests/conftest.py 不可修改，评测以测试为准。
- src/cdn/token.py 是唯一实现文件，恰好 8 个桩，初始全部 raise NotImplementedError。
- 按题面中 10 个缺陷的顺序逐个修复，不要改变测试预期。

## src 布局

```text
sec-cdn-token/
  README.md
  pyproject.toml
  tests/
    conftest.py
    test_token.py
  src/
    cdn/
      __init__.py
      token.py
```

- src/cdn/token.py：唯一实现文件，8 个函数依次为 normalize_path、token_scope、sign_token、verify_token、referer_ok、expiry_ok、validate_policy、cdn_batch；docstring 写明令牌格式、路径段通配和容差 0。
- src/cdn/__init__.py：包标记。
- tests/conftest.py：把 src 加入导入路径。
- tests/test_token.py：15 个测试；前 10 个对应题面的 10 个缺陷，后 5 个覆盖正确令牌、跨目录访问、过期令牌、仿冒来源、两批独立校验。

## 测试与缺陷对应

| 测试 | 覆盖点 |
| --- | --- |
| test_defect_01_query_string_is_removed | 去查询串 |
| test_defect_02_duplicate_slashes_are_collapsed | 折叠重复斜杠 |
| test_defect_03_scope_is_not_the_site_root | 作用域不取根目录 |
| test_defect_04_scope_prefix_respects_path_boundary | 前缀按路径段边界 |
| test_defect_05_token_carries_expiry | 令牌包含过期时间 |
| test_defect_06_expiry_boundary_is_rejected | 到期边界容差 0 |
| test_defect_07_ttl_upper_bound_is_enforced | 有效期上限 |
| test_defect_08_referer_suffix_spoofing_is_rejected | 来源后缀仿冒 |
| test_defect_09_policy_scope_too_wide_is_reported | 策略作用域过宽 |
| test_defect_10_batch_does_not_reuse_previous_scope | 批量不复用作用域 |
| test_valid_token_passes | 正确令牌通过 |
| test_cross_directory_token_is_rejected | 跨目录被拒 |
| test_expired_token_is_rejected | 过期令牌被拒 |
| test_spoofed_referer_is_rejected | 仿冒来源被拒 |
| test_batches_independent_match_individual | 批量与单独校验一致 |

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |
