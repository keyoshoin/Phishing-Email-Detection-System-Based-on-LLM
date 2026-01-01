"""
配置文件
"""
import os
from pathlib import Path

# 基础路径
BASE_DIR = Path(__file__).parent.absolute()
UPLOAD_FOLDER = BASE_DIR / 'uploads'
DATA_FOLDER = BASE_DIR / 'data'
MODEL_FOLDER = BASE_DIR / 'models' / 'saved_models'

# 创建必要的目录
UPLOAD_FOLDER.mkdir(exist_ok=True)
DATA_FOLDER.mkdir(exist_ok=True)
MODEL_FOLDER.mkdir(parents=True, exist_ok=True)

# Flask配置
SECRET_KEY = 'your-secret-key-change-in-production'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB

# LLM配置（可选）
# 如果使用OpenAI API，请设置以下配置
USE_OPENAI = False  # 设置为True启用GPT增强检测
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
OPENAI_MODEL = 'gpt-3.5-turbo'

# 模型配置
BERT_MODEL_NAME = 'bert-base-uncased'  # 或使用中文模型：'bert-base-chinese'
MAX_SEQUENCE_LENGTH = 512

# 特征提取配置
PHISHING_KEYWORDS = [
    'urgent', 'verify', 'account', 'suspended', 'click here', 'confirm',
    'password', 'security', 'update', 'expire', 'limited time', 'act now',
    'congratulations', 'winner', 'prize', 'free', 'claim', 'bonus',
    '紧急', '验证', '账户', '暂停', '点击', '确认', '密码', '安全',
    '更新', '过期', '限时', '恭喜', '中奖', '奖品', '免费', '领取'
]

# URL特征配置
SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
TRUSTED_DOMAINS = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']

# 检测阈值
PHISHING_THRESHOLD = 0.6  # 风险阈值，超过此值判定为钓鱼邮件
HIGH_RISK_THRESHOLD = 0.8  # 高风险阈值
LOW_RISK_THRESHOLD = 0.4   # 低风险阈值

# 调试模式
DEBUG = True
