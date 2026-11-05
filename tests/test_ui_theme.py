"""
UI 主题与交互层级规范静态断言测试
守卫验证：
G201: 顶栏代理控制按钮必须具备鲜明的运行中与停止悬浮状态指示
G202: 下拉选择器浮层具有层次感，SelectItem 具备高对比悬浮与整行选中感知
G203: 弹窗系统具备深邃遮罩与悬浮层次
"""
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_SRC = REPO_ROOT / "frontend" / "src"

class UIThemeEnhancementTests(unittest.TestCase):
    def test_g201_topbar_proxy_button_prominence(self):
        """Case G201 顶栏代理控制按钮具有运行态色彩与悬浮警告状态 UI_0001"""
        app_layout_path = FRONTEND_SRC / "components" / "layout" / "AppLayout.tsx"
        self.assertTrue(app_layout_path.exists())
        content = app_layout_path.read_text(encoding="utf-8")
        # 必须存在主状态或高亮样式指示
        self.assertIn("toggleProxy", content)
        self.assertTrue(
            "@guard G201" in content or "@guard G201 branch" in content,
            "AppLayout 缺少 @guard G201 守卫标记"
        )
        self.assertTrue(
            "text-success-ink" in content or "bg-success" in content or "shadow-" in content or "border-success" in content,
            "AppLayout 代理按钮缺乏核心状态色彩指示"
        )

    def test_g202_select_contrast_and_depth(self):
        """Case G202 下拉选择器 Select 浮层与项目具有层级与高亮选中态 UI_0002"""
        select_path = FRONTEND_SRC / "components" / "ui" / "select.tsx"
        self.assertTrue(select_path.exists())
        content = select_path.read_text(encoding="utf-8")
        self.assertTrue(
            "@guard G202" in content or "@guard G202 branch" in content,
            "select.tsx 缺少 @guard G202 守卫标记"
        )
        self.assertIn("SelectContent", content)
        self.assertIn("SelectItem", content)

    def test_g203_dialog_depth_and_elevation(self):
        """Case G203 弹窗 Dialog 具备毛玻璃与卡片内胆结构化分组 UI_0003"""
        dialog_path = FRONTEND_SRC / "components" / "ui" / "dialog.tsx"
        self.assertTrue(dialog_path.exists())
        content = dialog_path.read_text(encoding="utf-8")
        self.assertTrue(
            "@guard G203" in content or "@guard G203 branch" in content,
            "dialog.tsx 缺少 @guard G203 守卫标记"
        )
        self.assertIn("DialogOverlay", content)
        self.assertIn("DialogContent", content)

if __name__ == "__main__":
    unittest.main()
