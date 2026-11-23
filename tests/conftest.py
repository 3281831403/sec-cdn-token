"""把 src 布局加入导入路径，使测试无需安装包即可离线运行。"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))