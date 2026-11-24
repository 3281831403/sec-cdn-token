"""CDN 防盗链令牌的唯一实现文件。

全局约定：
- 时间一律由调用方显式传入，单位为 Unix 秒整数；不读取系统时间，不使用随机数。
- 作用域按路径段覆盖：scope 覆盖自身以及 scope 加一个斜杠之后的所有路径；
  根作用域 / 覆盖全部路径。
- 有效期容差为 0：now 等于 expires 即视为过期，剩余时间超出上限 1 秒即拒绝。
"""

import hashlib
import hmac
import re
from urllib.parse import urlsplit


def _scope_covers(parent: str, child: str) -> bool:
    """路径段边界判定：parent 作用域是否覆盖 child 作用域。

    相等、parent 为根、或 child 以 parent 加斜杠开头才算覆盖；
    纯字符串前缀（如 /video 命中 /video2）不算。
    """
    if parent == child:
        return True
    if parent == "/":
        return True
    return child.startswith(parent + "/")


def normalize_path(path: str) -> str:
    """规范化请求路径。

    契约：
    - 截断第一个问号或井号及其后的全部内容，去掉查询串与片段。
    - 把连续多个斜杠折叠成一个斜杠。
    - 结果保证以斜杠开头；空输入返回根路径 /。
    - 保留末尾的单个斜杠作为目录标记，根路径除外。
    - 不解析点段，不做 URL 解码，不改变大小写。
    - 容差 0：除上述变换外不丢弃任何字符。

    示例：//video///a.mp4?token=abc 规范化后为 /video/a.mp4。
    """
    # 缺陷 1：去掉查询串与片段，取问号、井号中最先出现的位置
    if not isinstance(path, str) or path == "":
        return "/"
    cut = len(path)
    for sep in ("?", "#"):
        idx = path.find(sep)
        if idx != -1 and idx < cut:
            cut = idx
    path = path[:cut]

    # 缺陷 2：折叠连续重复斜杠，杜绝 // 绕道路径
    path = re.sub(r"/+", "/", path)
    if path == "":
        return "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def token_scope(path: str) -> str:
    """返回路径对应的令牌作用域，取目录前缀或文件全路径。

    契约：
    - 先调用 normalize_path。
    - 末尾带斜杠且不是根路径时视为目录，去掉末尾斜杠后返回，
      例如 /video/2024/ 返回 /video/2024。
    - 根路径 / 返回 /。
    - 其余视为文件，返回完整规范化路径，例如 /video/2024/a.mp4。
    - 作用域是路径段通配的子树根：/video 覆盖 /video 本身与 /video/ 下的
      所有路径，但不覆盖 /video2 或 /video2/a.mp4。
    - 不使用星号字符，也不按扩展名猜测目录或文件。
    """
    # 缺陷 3：作用域按请求路径逐段收敛，不再整站共用根作用域
    normalized = normalize_path(path)
    if normalized == "/":
        return "/"
    if normalized.endswith("/"):
        return normalized[:-1]
    return normalized


def sign_token(secret: str, scope: str, expires: int) -> str:
    """生成令牌。

    令牌格式固定为 scope:expires:mac，三段以英文冒号分隔：
    - scope 为 token_scope 返回的作用域，不得包含冒号；
    - expires 为十进制 Unix 秒；
    - mac 为 HMAC-SHA256，密钥是 secret 的 UTF-8 字节，消息是
      scope:expires 的 UTF-8 字节，输出 64 位小写十六进制。

    不读取系统时间，不使用随机数；相同输入必须产生相同令牌。
    """
    # 缺陷 5：令牌正文携带过期时间，参与签名，无法被剥离或篡改
    body = f"{scope}:{expires}"
    mac = hmac.new(
        secret.encode("utf-8"),
        body.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"{body}:{mac}"


def verify_token(secret: str, token: str, scope: str, now: int) -> bool:
    """校验令牌对给定作用域是否有效。

    返回 True 当且仅当以下条件全部满足：
    1. token 符合 scope:expires:mac 格式，且 expires 能解析为整数；
    2. 用 secret 重算的 mac 与令牌中的 mac 常量时间相等；
    3. 令牌作用域覆盖请求作用域：两者相等，或令牌作用域为 /，或请求作用域
       以令牌作用域加斜杠开头。必须按路径段边界比较，纯字符串前缀不算覆盖；
    4. now 严格小于 expires。容差 0：now 等于 expires 即判过期。

    格式错误、签名错误、作用域不匹配或已过期都返回 False，不抛异常。
    """
    try:
        if not isinstance(token, str) or not isinstance(secret, str):
            return False
        parts = token.split(":")
        if len(parts) != 3:
            return False
        issued_scope, expires_text, mac = parts
        expires = int(expires_text)

        expected_mac = hmac.new(
            secret.encode("utf-8"),
            f"{issued_scope}:{expires}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(mac, expected_mac):
            return False

        # 缺陷 4：按路径段边界判覆盖，/video 不再命中 /video2
        if not _scope_covers(issued_scope, scope):
            return False

        # 缺陷 6：严格小于，now == expires 即过期，容差为 0
        return now < expires
    except Exception:
        return False


def referer_ok(referer: str, allow: list[str]) -> bool:
    """判断来源页是否在允许列表内。

    契约：
    - referer 为完整 URL 或 None；用 urllib.parse.urlsplit 取 hostname，
      忽略协议、端口、路径与大小写。
    - allow 中每项是精确主机名，或以星号加点开头的子域通配，
      例如 *.example.com。
    - 精确项要求 host 完全相等；通配项要求 host 以点加后缀结尾，并且
      host 不等于后缀本身，即至少有一级子域。星号只允许出现在最前面一次。
    - 空 referer、空 allow、单独的星号或非法通配一律返回 False。
    - 禁止只用字符串后缀比较：example.com 不得命中 evil-example.com、
      notexample.com 或 example.com.evil.test。
    """
    # 缺陷 8：精确主机名或路径段式子域通配，杜绝后缀仿冒
    if not referer or not allow:
        return False
    try:
        host = urlsplit(referer).hostname
    except ValueError:
        return False
    if not host:
        return False
    # 单独的星号等于不限制来源，失败闭合一律拒绝
    if "*" in allow:
        return False

    for item in allow:
        if not isinstance(item, str) or item == "":
            continue
        if item.startswith("*."):
            suffix = item[2:]
            # 星号只允许在最前面出现一次，否则是非法通配
            if not suffix or "*" in suffix:
                continue
            if host != suffix and host.endswith("." + suffix):
                return True
        else:
            if "*" in item:
                continue
            if host == item:
                return True
    return False


def expiry_ok(expires: int, now: int, max_ttl: int) -> bool:
    """判定有效期与上限是否同时合格。

    返回 True 当且仅当 now 严格小于 expires，并且 expires 减 now 不超过
    max_ttl。容差 0：now 等于 expires 判为过期；剩余时间恰好等于 max_ttl
    允许，多 1 秒即拒绝。max_ttl 非正时返回 False。参数不是整数时返回 False。
    """
    # 缺陷 6、7：到期边界严格小于，且剩余寿命不得超过签发上限
    if not all(
        isinstance(value, int) and not isinstance(value, bool)
        for value in (expires, now, max_ttl)
    ):
        return False
    if max_ttl <= 0:
        return False
    if now >= expires:
        return False
    return expires - now <= max_ttl


def validate_policy(policy: dict) -> list[str]:
    """检查策略配置，返回问题代码列表。

    识别的字段为 secret、allow、max_ttl、scope。问题代码按以下固定顺序
    返回，每类最多出现一次：
    - no_referer：allow 缺失、为空，或包含单独的星号，等于不限制来源；
    - ttl_too_long：max_ttl 缺失、不是正整数，或大于 86400 秒；
    - scope_too_wide：scope 缺失、规范化后为根路径，或只有一级目录，
      例如 / 或 /video；至少两级目录，例如 /video/2024，才算合格。

    没有任何问题时返回空列表。未知字段忽略。
    """
    if not isinstance(policy, dict):
        return ["no_referer", "ttl_too_long", "scope_too_wide"]

    problems = []

    allow = policy.get("allow")
    if not allow or "*" in allow:
        problems.append("no_referer")

    ttl = policy.get("max_ttl")
    if (
        not isinstance(ttl, int)
        or isinstance(ttl, bool)
        or ttl <= 0
        or ttl > 86400
    ):
        problems.append("ttl_too_long")

    # 缺陷 9：根作用域或只有一级目录的作用域一律判为过宽
    raw_scope = policy.get("scope")
    scope = token_scope(raw_scope) if isinstance(raw_scope, str) else "/"
    levels = [segment for segment in scope.split("/") if segment]
    if len(levels) < 2:
        problems.append("scope_too_wide")

    return problems


def cdn_batch(requests: list[dict], policy: dict, now: int) -> dict:
    """批量校验多个请求，逐项独立返回结果。

    每个请求包含 path、referer、token 三个字段。对每个请求单独执行：
    1. 用 normalize_path 与 token_scope 计算该请求的路径作用域，
       不得复用其他请求的作用域；
    2. 令牌作用域必须被 policy 的 scope 覆盖，且令牌作用域必须覆盖该请求路径；
    3. verify_token 校验签名、作用域与过期时间；
    4. referer_ok 校验来源；
    5. 从令牌中解析 expires，用 expiry_ok 校验 now 与 policy 的 max_ttl。

    全部通过记 True，否则记 False；坏令牌、缺字段、非字典请求都记 False，
    不抛异常。返回字典，键为请求下标，从 0 开始，值为布尔结果；空请求列表
    返回空字典。不同请求、不同批次之间不得共享作用域或校验状态。
    """
    if not isinstance(requests, list):
        return {}

    if not isinstance(policy, dict):
        secret, allow, max_ttl, policy_scope = "", [], 0, "/"
    else:
        secret = policy.get("secret", "")
        allow = policy.get("allow", [])
        max_ttl = policy.get("max_ttl", 0)
        raw_scope = policy.get("scope")
        policy_scope = token_scope(raw_scope) if isinstance(raw_scope, str) else "/"

    results = {}
    for index, request in enumerate(requests):
        try:
            if not isinstance(request, dict):
                results[index] = False
                continue

            # 缺陷 10：每个请求独立计算作用域，绝不复用上一个请求的结果
            request_scope = token_scope(request["path"])
            token = request["token"]
            parts = token.split(":")
            if len(parts) != 3:
                results[index] = False
                continue
            issued_scope, expires_text, _mac = parts
            try:
                expires = int(expires_text)
            except ValueError:
                results[index] = False
                continue

            # 策略作用域覆盖令牌作用域，令牌作用域再覆盖请求路径
            if not _scope_covers(policy_scope, issued_scope):
                results[index] = False
                continue
            if not _scope_covers(issued_scope, request_scope):
                results[index] = False
                continue
            if not verify_token(secret, token, request_scope, now):
                results[index] = False
                continue
            if not referer_ok(request.get("referer"), allow):
                results[index] = False
                continue
            if not expiry_ok(expires, now, max_ttl):
                results[index] = False
                continue

            results[index] = True
        except Exception:
            results[index] = False
    return results
