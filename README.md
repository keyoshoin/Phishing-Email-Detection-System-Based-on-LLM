# 🛡️ 基于LLM的钓鱼邮件检测系统

> 面向混合威胁的智能检测平台 - 网络安全技术课程实践项目

## 📋 项目简介

本系统能够有效检测：
- ✅ 传统钓鱼攻击
- ✅ LLM生成的钓鱼邮件
- ✅ 混合攻击链

采用**传统特征 + 机器学习 + LLM**三重检测机制，提供准确的风险评估和安全建议。

---

## 🚀 快速开始

### 方法1：一键启动
```bash
# Windows
run.bat

# Linux/Mac
chmod +x run.sh && ./run.sh
```

### 方法2：手动启动
```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动系统
python app.py

# 3. 浏览器访问
http://localhost:5000
```

**注意**: 首次运行会下载BERT模型，需要等待几分钟。

---

## ✨ 核心功能

### 1. 邮件上传
- 📝 文本直接输入
- 📁 文件上传（.txt, .eml）
- 🖱️ 拖放支持
- 📋 示例邮件

### 2. 智能检测
- **传统特征**: URL、HTML、关键词分析
- **语义理解**: BERT深度学习模型
- **LLM增强**: GPT高级分析（可选）

### 3. 结果展示
- 📊 风险评分 (0-100)
- 🎯 分类结果（钓鱼/正常）
- ⚠️ 风险点列表
- 💡 安全建议

---

## 🏗️ 系统架构

```
数据输入 → 特征提取 → 混合检测 → 结果输出
   │          │          │          │
 文本/文件  URL/HTML   规则/ML    评分/建议
           关键词     LLM分析
           BERT语义
```

---

## 📁 项目结构

```
program/
├── app.py                    # Flask主程序 ⭐
├── config.py                 # 配置文件
├── requirements.txt          # 依赖列表
├── test.py                   # 测试脚本
│
├── models/                   # 核心模块 ⭐
│   ├── feature_extractor.py # 特征提取
│   ├── detector.py          # 检测模型
│   └── llm_analyzer.py      # LLM分析
│
├── utils/                    # 工具函数
│   └── helpers.py
│
├── templates/                # 前端页面 ⭐
│   └── index.html
│
├── static/                   # 前端资源 ⭐
│   ├── css/style.css
│   └── js/main.js
│
└── data/                     # 示例数据
    └── sample_emails.json
```

---

## 🔧 配置说明

### 基础配置
在 `config.py` 中可修改：
- `PHISHING_THRESHOLD`: 检测阈值（默认0.6）
- `PHISHING_KEYWORDS`: 钓鱼关键词列表
- `SUSPICIOUS_TLDS`: 可疑域名后缀

### 启用LLM增强（可选）
```python
# config.py
USE_OPENAI = True
OPENAI_API_KEY = 'your-api-key-here'
```

或设置环境变量：
```bash
export OPENAI_API_KEY='your-api-key-here'
```

---

## 📡 API接口

### 检测邮件
```bash
POST /api/detect
Content-Type: application/json

{
  "email_content": "邮件内容"
}
```

**响应示例**:
```json
{
  "success": true,
  "result": {
    "is_phishing": true,
    "risk_score": 85.5,
    "confidence": 92.3,
    "risk_level": "高风险",
    "suggestions": ["不要点击链接", "验证发件人"]
  }
}
```

### 其他接口
- `POST /api/upload` - 文件上传检测
- `POST /api/batch_detect` - 批量检测
- `POST /api/report` - 生成详细报告
- `GET /api/health` - 健康检查

---

## 🧪 运行测试

```bash
python test.py
```

测试包括：
- 单个邮件检测
- 批量检测
- 特征提取
- 报告生成

---

## 🛠️ 技术栈

| 类型 | 技术 |
|------|------|
| 后端 | Flask 3.0, Python 3.8+ |
| 机器学习 | scikit-learn, Random Forest |
| 深度学习 | PyTorch, Transformers, BERT |
| HTML解析 | BeautifulSoup4 |
| 前端 | HTML5, CSS3, JavaScript |
| LLM | OpenAI API (可选) |

---

## 💡 使用技巧

### 提高检测准确率
1. **训练自定义模型**
```python
from models.detector import get_detector

detector = get_detector()
detector.train(texts, labels)  # texts: 邮件列表, labels: 0/1标签
```

2. **调整检测阈值**
```python
# config.py
PHISHING_THRESHOLD = 0.7  # 默认0.6，调高则更严格
```

3. **添加自定义关键词**
```python
# config.py
PHISHING_KEYWORDS = [
    'urgent', 'verify', 'suspended',
    '紧急', '验证', '暂停',
    # 添加你的关键词
]
```

---

## ❓ 常见问题

**Q: BERT模型下载很慢？**  
A: 使用国内镜像或手动下载到 `~/.cache/huggingface/`

**Q: 检测不准确？**  
A: 1) 收集数据训练自定义模型 2) 启用LLM增强 3) 调整阈值

**Q: 支持哪些语言？**  
A: 支持中文和英文

**Q: 可以离线使用吗？**  
A: 可以，LLM功能是可选的

---

## 📊 功能演示

1. **加载示例** → 点击"加载示例"按钮
2. **开始检测** → 查看风险评分和详细分析
3. **生成报告** → 下载完整的检测报告

---

## 📝 系统要求

- Python 3.8+
- 2GB+ RAM
- 网络连接（首次下载BERT模型）

---

## 👨‍💻 开发者

网络安全技术课程实践项目  
版本: v1.0.0  
日期: 2026年1月1日

---

## 📄 许可证

本项目仅用于教育和研究目的。
