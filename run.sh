#!/bin/bash

echo "========================================"
echo "钓鱼邮件检测系统"
echo "========================================"
echo ""

# 检查Python是否安装
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未检测到Python3，请先安装Python 3.8+"
    exit 1
fi

echo "[1/3] 检查依赖..."
python3 -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[提示] 正在安装依赖，请稍候..."
    pip3 install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[错误] 依赖安装失败"
        exit 1
    fi
fi

echo "[2/3] 运行测试..."
python3 test.py
if [ $? -ne 0 ]; then
    echo "[警告] 测试未完全通过，但可以继续运行"
fi

echo ""
echo "[3/3] 启动系统..."
echo ""
echo "========================================"
echo "系统启动成功！"
echo "请在浏览器中访问: http://localhost:5000"
echo "按 Ctrl+C 可停止服务"
echo "========================================"
echo ""

python3 app.py
