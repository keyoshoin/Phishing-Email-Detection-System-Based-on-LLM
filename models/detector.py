"""
检测模型
实现基于机器学习和规则的钓鱼邮件检测
"""
import numpy as np
from typing import Dict, Any, Tuple
import pickle
import warnings
warnings.filterwarnings('ignore')

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from models.feature_extractor import HybridFeatureExtractor
from models.llm_analyzer import LLMAnalyzer
from models.hybrid_attack_detector import HybridAttackDetector
from models.llm_attack_detector import LLMAttackDetector
from utils.helpers import format_detection_result
from config import PHISHING_THRESHOLD, HIGH_RISK_THRESHOLD, LOW_RISK_THRESHOLD


class PhishingDetector:
    """钓鱼邮件检测器"""

    def __init__(self):
        self.feature_extractor = HybridFeatureExtractor()
        self.llm_analyzer = LLMAnalyzer()
        self.hybrid_detector = HybridAttackDetector()
        self.llm_attack_detector = LLMAttackDetector()
        self.ml_model = None
        self.scaler = None
        self.model_trained = False

        # 尝试加载预训练模型
        self._load_model()
    
    def _load_model(self):
        """加载预训练模型"""
        try:
            from pathlib import Path
            from config import MODEL_FOLDER
            
            model_path = Path(MODEL_FOLDER) / 'phishing_detector.pkl'
            scaler_path = Path(MODEL_FOLDER) / 'scaler.pkl'
            
            if model_path.exists() and scaler_path.exists():
                with open(model_path, 'rb') as f:
                    self.ml_model = pickle.load(f)
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                self.model_trained = True
                print("已加载预训练模型")
        except Exception as e:
            print(f"加载模型失败，将使用规则检测: {e}")
    
    def _save_model(self):
        """保存模型"""
        try:
            from pathlib import Path
            from config import MODEL_FOLDER
            
            model_path = Path(MODEL_FOLDER) / 'phishing_detector.pkl'
            scaler_path = Path(MODEL_FOLDER) / 'scaler.pkl'
            
            with open(model_path, 'wb') as f:
                pickle.dump(self.ml_model, f)
            with open(scaler_path, 'wb') as f:
                pickle.dump(self.scaler, f)
            print("模型已保存")
        except Exception as e:
            print(f"保存模型失败: {e}")
    
    def train(self, texts: list, labels: list):
        """训练模型"""
        if not SKLEARN_AVAILABLE:
            print("scikit-learn未安装，无法训练模型")
            return
        
        print(f"开始训练模型，样本数: {len(texts)}")
        
        # 提取特征
        X = []
        for text in texts:
            features = self.feature_extractor.extract_features(text)
            feature_vector = self.feature_extractor.get_feature_vector(features)
            X.append(feature_vector)
        
        X = np.array(X)
        y = np.array(labels)
        
        # 标准化
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # 训练随机森林
        self.ml_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.ml_model.fit(X_scaled, y)
        
        self.model_trained = True
        self._save_model()
        
        # 计算准确率
        accuracy = self.ml_model.score(X_scaled, y)
        print(f"模型训练完成，训练准确率: {accuracy:.2%}")
    
    def _rule_based_detection(self, features: Dict[str, Any]) -> Tuple[float, float]:
        """基于规则的检测"""
        risk_score = 0.0
        max_score = 100.0
        
        trad = features.get('traditional', {})
        
        # URL特征评分
        url_feats = trad.get('url', {})
        suspicious_url_ratio = url_feats.get('suspicious_url_ratio', 0)
        if suspicious_url_ratio > 0:
            risk_score += 25 * suspicious_url_ratio
        
        if url_feats.get('has_ip_url'):
            risk_score += 15
        
        if url_feats.get('url_count', 0) > 5:
            risk_score += 10
        
        # 关键词特征评分
        keyword_feats = trad.get('keyword', {})
        keyword_count = keyword_feats.get('phishing_keyword_count', 0)
        risk_score += min(keyword_count * 3, 20)
        
        if keyword_feats.get('has_urgent_language'):
            risk_score += 15
        
        if keyword_feats.get('has_personal_info_request'):
            risk_score += 20
        
        if keyword_feats.get('has_monetary_terms'):
            risk_score += 10
        
        # HTML特征评分
        html_feats = trad.get('html', {})
        if html_feats.get('hidden_elements', 0) > 0:
            risk_score += 15
        
        if html_feats.get('form_count', 0) > 0:
            risk_score += 10
        
        if html_feats.get('script_tag_count', 0) > 2:
            risk_score += 10
        
        # 文本特征评分
        text_feats = trad.get('text', {})
        if text_feats.get('exclamation_count', 0) > 3:
            risk_score += 5
        
        if text_feats.get('uppercase_ratio', 0) > 0.3:
            risk_score += 10
        
        # 限制在0-100范围
        risk_score = min(risk_score, max_score)
        
        # 计算置信度
        confidence = 60 + (risk_score / max_score) * 30
        
        return risk_score, confidence
    
    def _ml_based_detection(self, features: Dict[str, Any]) -> Tuple[float, float]:
        """基于机器学习的检测"""
        try:
            # 提取特征向量
            feature_vector = self.feature_extractor.get_feature_vector(features)
            feature_vector = feature_vector.reshape(1, -1)
            
            # 标准化
            feature_vector_scaled = self.scaler.transform(feature_vector)
            
            # 预测
            probability = self.ml_model.predict_proba(feature_vector_scaled)[0]
            phishing_prob = probability[1] if len(probability) > 1 else probability[0]
            
            # 转换为风险评分
            risk_score = phishing_prob * 100
            confidence = max(probability) * 100
            
            return risk_score, confidence
        except Exception as e:
            print(f"ML检测失败，回退到规则检测: {e}")
            return self._rule_based_detection(features)
    
    def detect(self, text: str) -> Dict[str, Any]:
        """检测邮件是否为钓鱼邮件"""
        # 提取特征
        features = self.feature_extractor.extract_features(text)

        # 选择检测方法
        if self.model_trained and self.ml_model is not None:
            risk_score, confidence = self._ml_based_detection(features)
        else:
            risk_score, confidence = self._rule_based_detection(features)

        # 判断是否为钓鱼邮件
        is_phishing = risk_score >= (PHISHING_THRESHOLD * 100)

        # 使用LLM增强分析
        llm_analysis = self.llm_analyzer.analyze_with_gpt(text, features)

        # 检测LLM生成攻击
        llm_attack_result = self.llm_attack_detector.detect_llm_generated(text, features)
        llm_phishing_patterns = self.llm_attack_detector.detect_llm_phishing_pattern(text)

        # 检测混合攻击链
        hybrid_attack_result = self.hybrid_detector.detect_attack_chain(text, features)

        # 综合评分调整
        # 如果检测到LLM生成且是钓鱼邮件，提高风险评分
        if llm_attack_result['is_llm_generated'] and is_phishing:
            risk_score = min(risk_score * 1.1, 100)
            confidence = min(confidence * 1.05, 100)

        # 如果检测到混合攻击链，提高风险评分
        if hybrid_attack_result['is_hybrid_attack']:
            risk_score = min(risk_score * 1.15, 100)
            confidence = min(confidence * 1.1, 100)

        # 如果LLM和规则检测结果不一致，调整置信度
        if llm_analysis.get('is_phishing') != is_phishing:
            confidence = confidence * 0.8

        # 合并LLM的建议
        suggestions = llm_analysis.get('suggestions', [])

        # 添加针对LLM攻击和混合攻击的建议
        if llm_attack_result['is_llm_generated']:
            suggestions.append("警告：此邮件可能由AI生成，需特别谨慎")
        if hybrid_attack_result['is_hybrid_attack']:
            suggestions.append("警告：检测到混合攻击链特征，多阶段威胁")

        # 格式化结果
        result = format_detection_result(
            risk_score=risk_score,
            is_phishing=is_phishing,
            confidence=confidence,
            features=features,
            suggestions=suggestions
        )

        # 添加风险点
        result['risk_points'] = llm_analysis.get('risk_points', [])

        # 添加攻击检测详情
        result['llm_attack'] = llm_attack_result
        result['hybrid_attack'] = hybrid_attack_result

        # 更新攻击类型标签
        attack_types = []
        if llm_attack_result['is_llm_generated']:
            attack_types.append('LLM生成攻击')
        if hybrid_attack_result['is_hybrid_attack']:
            attack_types.append('混合攻击链')
        if not attack_types and is_phishing:
            attack_types.append('传统钓鱼攻击')
        result['attack_types'] = attack_types if attack_types else ['正常邮件']

        return result
    
    def batch_detect(self, texts: list) -> list:
        """批量检测"""
        results = []
        for text in texts:
            result = self.detect(text)
            results.append(result)
        return results
    
    def generate_report(self, text: str) -> str:
        """生成详细报告"""
        result = self.detect(text)
        features = result.get('features', {})

        # 基础报告
        report = self.llm_analyzer.generate_report(text, features, result)

        # 添加LLM攻击分析
        if result.get('llm_attack', {}).get('is_llm_generated'):
            llm_report = self.llm_attack_detector.generate_llm_attack_report(
                result['llm_attack'],
                self.llm_attack_detector.detect_llm_phishing_pattern(text)
            )
            report += "\n\n" + llm_report

        # 添加混合攻击链分析
        if result.get('hybrid_attack', {}).get('is_hybrid_attack'):
            hybrid_report = self.hybrid_detector.generate_attack_chain_report(
                result['hybrid_attack']
            )
            report += "\n\n" + hybrid_report

        # 添加攻击类型总结
        attack_types = result.get('attack_types', [])
        if attack_types and '正常邮件' not in attack_types:
            report += f"\n\n攻击类型: {', '.join(attack_types)}"

        return report


# 全局检测器实例
_detector_instance = None


def get_detector() -> PhishingDetector:
    """获取检测器单例"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = PhishingDetector()
    return _detector_instance
