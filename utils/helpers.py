"""
辅助工具函数
"""
import re
from typing import List, Dict, Any
from urllib.parse import urlparse
import tldextract


def extract_urls(text: str) -> List[str]:
    """从文本中提取URL"""
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, text)
    return urls


def extract_emails(text: str) -> List[str]:
    """从文本中提取邮箱地址"""
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    emails = re.findall(email_pattern, text)
    return emails


def extract_ip_addresses(text: str) -> List[str]:
    """从文本中提取IP地址"""
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, text)
    return ips


def is_suspicious_url(url: str, suspicious_tlds: List[str]) -> bool:
    """检查URL是否可疑"""
    try:
        extracted = tldextract.extract(url)
        tld = f'.{extracted.suffix}'
        
        # 检查可疑TLD
        if tld in suspicious_tlds:
            return True
        
        # 检查IP地址
        parsed = urlparse(url)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed.netloc):
            return True
        
        # 检查URL长度
        if len(url) > 75:
            return True
        
        # 检查特殊字符
        if '@' in url or '//' in url[8:]:
            return True
        
        return False
    except:
        return False


def count_special_chars(text: str) -> Dict[str, int]:
    """统计特殊字符数量"""
    return {
        'exclamation': text.count('!'),
        'question': text.count('?'),
        'dollar': text.count('$'),
        'percent': text.count('%'),
        'at': text.count('@'),
        'hash': text.count('#')
    }


def has_urgent_language(text: str) -> bool:
    """检测是否包含紧急语言"""
    urgent_patterns = [
        r'urgent', r'immediate', r'act now', r'limited time',
        r'expires?', r'deadline', r'hurry', r'quick',
        r'紧急', r'立即', r'马上', r'限时', r'过期', r'截止'
    ]
    
    text_lower = text.lower()
    for pattern in urgent_patterns:
        if re.search(pattern, text_lower):
            return True
    return False


def calculate_entropy(text: str) -> float:
    """计算文本熵（衡量随机性）"""
    from collections import Counter
    import math
    
    if not text:
        return 0.0
    
    # 统计字符频率
    counter = Counter(text)
    length = len(text)
    
    # 计算香农熵
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def normalize_score(score: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """标准化分数到指定范围"""
    normalized = max(min_val, min(max_val, score))
    return round(normalized, 2)


def format_detection_result(
    risk_score: float,
    is_phishing: bool,
    confidence: float,
    features: Dict[str, Any],
    suggestions: List[str] = None
) -> Dict[str, Any]:
    """格式化检测结果"""
    
    # 确定风险等级
    if risk_score >= 80:
        risk_level = "高风险"
        risk_color = "danger"
    elif risk_score >= 60:
        risk_level = "中风险"
        risk_color = "warning"
    elif risk_score >= 40:
        risk_level = "低风险"
        risk_color = "info"
    else:
        risk_level = "安全"
        risk_color = "success"
    
    return {
        'is_phishing': is_phishing,
        'risk_score': normalize_score(risk_score),
        'confidence': normalize_score(confidence),
        'risk_level': risk_level,
        'risk_color': risk_color,
        'classification': '钓鱼邮件' if is_phishing else '正常邮件',
        'features': features,
        'suggestions': suggestions or []
    }
