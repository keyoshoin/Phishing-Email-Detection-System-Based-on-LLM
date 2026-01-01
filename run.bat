@echo off
chcp 65001 >nul
echo ========================================
echo 钓鱼邮件检测系统
echo ========================================
echo.

REM 检查Python是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python，请先安装Python 3.8+
    pause
    exit /b 1
)

echo [1/3] 检查依赖...
python -c "import flask" >nul 2>&1
if errorlevel 1 (
    echo [提示] 正在安装依赖，请稍候...
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    if errorlevel 1 (
        echo [错误] 依赖安装失败
        pause
        exit /b 1
    )
)

echo [2/3] 运行测试...
python test.py
if errorlevel 1 (
    echo [警告] 测试未完全通过，但可以继续运行
)

echo.
echo [3/3] 启动系统...
echo.
echo ========================================
echo 系统启动成功！
echo 请在浏览器中访问: http://localhost:5000
echo 按 Ctrl+C 可停止服务
echo ========================================
echo.

python app.py

pause
