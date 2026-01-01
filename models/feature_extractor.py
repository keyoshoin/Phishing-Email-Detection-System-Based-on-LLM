"""
特征提取器
实现传统特征提取和语义特征提取
"""
import re
import numpy as np
from typing import Dict, List, Any, Tuple
from bs4 import BeautifulSoup
from collections import Counter
import warnings
warnings.filterwarnings('ignore')

try:
    from transformers import BertTokenizer, BertModel
    import torch
    BERT_AVAILABLE = True
except ImportError:
    BERT_AVAILABLE = False

from utils.helpers import (
    extract_urls, extract_emails, extract_ip_addresses,
    is_suspicious_url, count_special_chars, has_urgent_language,
    calculate_entropy
)
from config import (
    PHISHING_KEYWORDS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS,
    BERT_MODEL_NAME, MAX_SEQUENCE_LENGTH
)


class TraditionalFeatureExtractor:
    """传统特征提取器"""
    
    def __init__(self):
        self.phishing_keywords = PHISHING_KEYWORDS
        self.suspicious_tlds = SUSPICIOUS_TLDS
        self.trusted_domains = TRUSTED_DOMAINS
    
    def extract_url_features(self, text: str) -> Dict[str, Any]:
        """提取URL相关特征"""
        urls = extract_urls(text)
        
        features = {
            'url_count': len(urls),
            'has_url': len(urls) > 0,
            'suspicious_url_count': 0,
            'suspicious_url_ratio': 0.0,
            'has_ip_url': False,
            'url_lengths': []
        }
        
        if urls:
            suspicious_count = sum(1 for url in urls if is_suspicious_url(url, self.suspicious_tlds))
            features['suspicious_url_count'] = suspicious_count
            features['suspicious_url_ratio'] = suspicious_count / len(urls)
            features['url_lengths'] = [len(url) for url in urls]
            features['avg_url_length'] = np.mean(features['url_lengths'])
            features['max_url_length'] = max(features['url_lengths'])
            
            # 检查是否包含IP地址URL
            for url in urls:
                if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                    features['has_ip_url'] = True
                    break
        
        return features
    
    def extract_html_features(self, text: str) -> Dict[str, Any]:
        """提取HTML相关特征"""
        features = {
            'has_html': False,
            'html_tag_count': 0,
            'script_tag_count': 0,
            'form_count': 0,
            'iframe_count': 0,
            'hidden_elements': 0,
            'suspicious_attributes': 0
        }
        
        # 检测是否包含HTML
        if '<' in text and '>' in text:
            features['has_html'] = True
            
            try:
                soup = BeautifulSoup(text, 'lxml')
                
                # 统计各种标签
                features['html_tag_count'] = len(soup.find_all())
                features['script_tag_count'] = len(soup.find_all('script'))
                features['form_count'] = len(soup.find_all('form'))
                features['iframe_count'] = len(soup.find_all('iframe'))
                
                # 检测隐藏元素
                hidden = soup.find_all(style=re.compile(r'display\s*:\s*none', re.I))
                features['hidden_elements'] = len(hidden)
                
                # 检测可疑属性
                suspicious_attrs = ['onclick', 'onload', 'onerror']
                for tag in soup.find_all():
                    for attr in suspicious_attrs:
                        if tag.has_attr(attr):
                            features['suspicious_attributes'] += 1
                
            except Exception as e:
                pass
        
        return features
    
    def extract_keyword_features(self, text: str) -> Dict[str, Any]:
        """提取关键词特征"""
        text_lower = text.lower()
        
        # 统计钓鱼关键词
        keyword_matches = []
        for keyword in self.phishing_keywords:
            if keyword.lower() in text_lower:
                keyword_matches.append(keyword)
        
        features = {
            'phishing_keyword_count': len(keyword_matches),
            'phishing_keywords': keyword_matches,
            'has_urgent_language': has_urgent_language(text),
            'has_monetary_terms': any(term in text_lower for term in ['$', '¥', '€', 'money', 'cash', 'prize', '奖金', '现金']),
            'has_personal_info_request': any(term in text_lower for term in ['password', 'ssn', 'credit card', '密码', '信用卡', '身份证']),
        }
        
        return features
    
    def extract_text_features(self, text: str) -> Dict[str, Any]:
        """提取文本统计特征"""
        features = {
            'length': len(text),
            'word_count': len(text.split()),
            'sentence_count': len(re.split(r'[.!?]+', text)),
            'uppercase_ratio': sum(1 for c in text if c.isupper()) / max(len(text), 1),
            'digit_ratio': sum(1 for c in text if c.isdigit()) / max(len(text), 1),
            'entropy': calculate_entropy(text),
        }
        
        # 特殊字符统计
        special_chars = count_special_chars(text)
        features.update({f'{k}_count': v for k, v in special_chars.items()})
        
        return features
    
    def extract_email_features(self, text: str) -> Dict[str, Any]:
        """提取邮件地址特征"""
        emails = extract_emails(text)
        
        features = {
            'email_count': len(emails),
            'has_email': len(emails) > 0,
            'emails': emails
        }
        
        return features
    
    def extract_all_features(self, text: str) -> Dict[str, Any]:
        """提取所有传统特征"""
        features = {}
        
        features['url'] = self.extract_url_features(text)
        features['html'] = self.extract_html_features(text)
        features['keyword'] = self.extract_keyword_features(text)
        features['text'] = self.extract_text_features(text)
        features['email'] = self.extract_email_features(text)
        
        return features


class SemanticFeatureExtractor:
    """语义特征提取器（基于BERT）"""
    
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.available = BERT_AVAILABLE
        
        if self.available:
            try:
                print("正在加载BERT模型...")
                self.tokenizer = BertTokenizer.from_pretrained(BERT_MODEL_NAME)
                self.model = BertModel.from_pretrained(BERT_MODEL_NAME)
                self.model.eval()
                print("BERT模型加载完成")
            except Exception as e:
                print(f"BERT模型加载失败: {e}")
                self.available = False
    
    def extract_bert_embeddings(self, text: str) -> np.ndarray:
        """提取BERT嵌入向量"""
        if not self.available or self.model is None:
            # 返回随机向量作为替代
            return np.random.randn(768)
        
        try:
            # 截断文本
            if len(text) > MAX_SEQUENCE_LENGTH * 4:
                text = text[:MAX_SEQUENCE_LENGTH * 4]
            
            # 编码文本
            inputs = self.tokenizer(
                text,
                return_tensors='pt',
                max_length=MAX_SEQUENCE_LENGTH,
                truncation=True,
                padding=True
            )
            
            # 获取嵌入
            with torch.no_grad():
                outputs = self.model(**inputs)
                embeddings = outputs.last_hidden_state.mean(dim=1).squeeze().numpy()
            
            return embeddings
        except Exception as e:
            print(f"BERT特征提取失败: {e}")
            return np.random.randn(768)
    
    def extract_semantic_features(self, text: str) -> Dict[str, Any]:
        """提取语义特征"""
        embeddings = self.extract_bert_embeddings(text)
        
        features = {
            'bert_embeddings': embeddings,
            'embedding_dim': len(embeddings),
            'embedding_mean': float(np.mean(embeddings)),
            'embedding_std': float(np.std(embeddings)),
            'embedding_max': float(np.max(embeddings)),
            'embedding_min': float(np.min(embeddings))
        }
        
        return features


class HybridFeatureExtractor:
    """混合特征提取器（融合传统特征和语义特征）"""
    
    def __init__(self):
        self.traditional_extractor = TraditionalFeatureExtractor()
        self.semantic_extractor = SemanticFeatureExtractor()
    
    def extract_features(self, text: str) -> Dict[str, Any]:
        """提取所有特征"""
        # 提取传统特征
        traditional_features = self.traditional_extractor.extract_all_features(text)
        
        # 提取语义特征
        semantic_features = self.semantic_extractor.extract_semantic_features(text)
        
        # 合并特征
        features = {
            'traditional': traditional_features,
            'semantic': semantic_features,
            'raw_text': text
        }
        
        return features
    
    def get_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """将特征转换为向量（用于机器学习）"""
        vector = []
        
        # 传统特征向量化
        trad = features['traditional']
        
        # URL特征
        url_feats = trad['url']
        vector.extend([
            url_feats['url_count'],
            float(url_feats['has_url']),
            url_feats['suspicious_url_count'],
            url_feats['suspicious_url_ratio'],
            float(url_feats['has_ip_url']),
            url_feats.get('avg_url_length', 0),
            url_feats.get('max_url_length', 0)
        ])
        
        # HTML特征
        html_feats = trad['html']
        vector.extend([
            float(html_feats['has_html']),
            html_feats['html_tag_count'],
            html_feats['script_tag_count'],
            html_feats['form_count'],
            html_feats['iframe_count'],
            html_feats['hidden_elements'],
            html_feats['suspicious_attributes']
        ])
        
        # 关键词特征
        keyword_feats = trad['keyword']
        vector.extend([
            keyword_feats['phishing_keyword_count'],
            float(keyword_feats['has_urgent_language']),
            float(keyword_feats['has_monetary_terms']),
            float(keyword_feats['has_personal_info_request'])
        ])
        
        # 文本特征
        text_feats = trad['text']
        vector.extend([
            text_feats['length'],
            text_feats['word_count'],
            text_feats['sentence_count'],
            text_feats['uppercase_ratio'],
            text_feats['digit_ratio'],
            text_feats['entropy']
        ])
        
        # 语义特征（使用统计量而非完整嵌入）
        sem = features['semantic']
        vector.extend([
            sem['embedding_mean'],
            sem['embedding_std'],
            sem['embedding_max'],
            sem['embedding_min']
        ])
        
        return np.array(vector)
