@echo off
echo ========================================
echo API中转站投毒检测监控程序
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo 错误: 未找到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

REM 安装依赖
echo 正在安装依赖...
pip install -r requirements.txt -q

echo.
echo 可用命令:
echo.
echo 1. 启动监控代理:
echo    python cli.py monitor --relay-url https://your-relay-url.com --api-key your-key
echo.
echo 2. 运行攻击演示:
echo    python cli.py demo --attack all
echo.
echo 3. 快速检查中转站:
echo    python cli.py check --relay-url https://your-relay-url.com
echo.
echo 4. 分析请求文件:
echo    python cli.py analyze --file request.json
echo.
echo ========================================
echo.
pause
