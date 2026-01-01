"""
LLM生成攻击检测器
专门检测大语言模型生成的钓鱼邮件
"""
import re
import numpy as np
from typing import Dict, List, Any, Tuple
from collections import Counter


class LLMAttackDetector:
    """LLM生成攻击检测器"""

    def __init__(self):
        # LLM生成的文本特征
        self.llm_indicators = {
            'perfect_grammar': 0.25,
            'balanced_structure': 0.15,
            'generic_phrases': 0.35,  # 提高权重
            'polite_tone': 0.15,
            'low_entropy': 0.1
        }

        # 扩充的LLM生成短语库
        self.llm_phrases = [
            # 通用礼貌短语
            'Thank you for your',
            'We appreciate your',
            'Please note that',
            'As part of our',
            'To ensure security',
            'This is a standard',
            'We apologize for any',
            'Thank you for your patience',
            'We value your',
            'Please do not hesitate',
            # 新增LLM特征短语
            'We are writing to inform you',
            'We hope this message finds you',
            'We hope you are having',
            'We are committed to',
            'We are writing to bring to your attention',
            'We would like to inform you',
            'Please take a moment to',
            'Thank you for being a valued',
            'Thank you for your continued',
            'Thank you for your prompt attention',
            'We appreciate your cooperation',
            'We appreciate your understanding',
            'Your prompt attention to this matter',
            'Should you have any questions',
            'If you have any questions or concerns',
            'Should you require any assistance',
            'Please feel free to',
            'Don\'t hesitate to contact',
            'We are available to assist you',
            'We are here to help',
            'This is a one-time process',
            'This is a routine process',
            'This is a standard procedure',
            'For your security',
            'To protect your account',
            'To ensure continued security',
            'As a security measure',
            'For security reasons',
            'without your explicit',
            'without your permission',
            'unauthorized access to',
            'protect your personal and financial',
            'safeguard your information',
            'industry-standard encryption',
            'highest security standards',
            'state-of-the-art security',
            'latest encryption technology',
            'take only a few minutes',
            'typically takes only',
            'should take no more than',
            'designed to be straightforward',
            'designed to be user-friendly',
            'designed to be convenient',
            'simply complete the following',
            'simply visit our',
            'just click on the',
            'follow the instructions below',
            'follow steps outlined',
            'is designed to ensure',
            'is designed to protect',
            'is designed to help',
            'to help us maintain',
            'to help ensure',
            'to better protect',
            'to better serve',
            'for your convenience',
            'for your protection',
            'for your safety',
            'simple and efficient',
            'user-friendly process',
            'straightforward and user-friendly',
        ]

        # LLM生成邮件的典型结构
        self.llm_structure_patterns = [
            r'(Dear|Dear Valued).*,\n\n.{10,}\n\n.{10,}\n\n.{10,}',
            r'.{50,}\n\n.{20,}\n\n.{20,}\n\n.{20,}',
        ]

    def detect_llm_generated(self, text: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """检测是否为LLM生成的邮件"""
        result = {
            'is_llm_generated': False,
            'llm_score': 0.0,
            'confidence': 0.0,
            'indicators': {},
            'evidence': []
        }

        # 1. 检测语法质量
        grammar_score = self._check_grammar_quality(text)
        result['indicators']['perfect_grammar'] = grammar_score

        # 2. 检测文本结构
        structure_score = self._check_text_structure(text)
        result['indicators']['balanced_structure'] = structure_score

        # 3. 检测LLM短语
        phrase_score = self._check_llm_phrases(text)
        result['indicators']['generic_phrases'] = phrase_score

        # 4. 检测语气
        tone_score = self._check_polite_tone(text)
        result['indicators']['polite_tone'] = tone_score

        # 5. 检测熵值
        entropy_score = self._check_entropy(features)
        result['indicators']['low_entropy'] = entropy_score

        # 6. 收集证据
        result['evidence'] = self._collect_evidence(text, result['indicators'])

        # 计算综合评分
        result['llm_score'] = self._calculate_llm_score(result['indicators'])
        result['is_llm_generated'] = result['llm_score'] > 0.65  # 降低阈值提高召回率
        result['confidence'] = result['llm_score'] * 100

        return result

    def _check_grammar_quality(self, text: str) -> float:
        """检查语法质量"""
        # 简化的语法检查 - 统计常见错误
        grammar_errors = 0
        total_sentences = len(re.split(r'[.!?]+', text))

        # 检查大小写错误
        if re.search(r'\.\s[a-z]', text):  # 句首小写
            grammar_errors += 1

        # 检查重复单词
        words = text.lower().split()
        for i in range(len(words) - 1):
            if words[i] == words[i + 1] and len(words[i]) > 2:
                grammar_errors += 1

        # 计算分数
        if total_sentences > 0:
            error_rate = grammar_errors / total_sentences
            return max(0, 1 - error_rate * 5)  # 错误越少分数越高
        return 0.5

    def _check_text_structure(self, text: str) -> float:
        """检查文本结构"""
        # 分割段落
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]

        if len(paragraphs) < 2:
            return 0.0

        # 检查段落长度是否均衡
        lengths = [len(p) for p in paragraphs]
        mean_length = np.mean(lengths)
        std_length = np.std(lengths)

        # 标准差越小，结构越均衡
        if mean_length > 0:
            balance_score = max(0, 1 - std_length / mean_length)
            return balance_score * 0.8  # 最高0.8
        return 0.0

    def _check_llm_phrases(self, text: str) -> float:
        """检查LLM常用短语"""
        text_lower = text.lower()
        phrase_count = 0

        for phrase in self.llm_phrases:
            if phrase.lower() in text_lower:
                phrase_count += 1

        # 归一化，降低匹配阈值
        return min(phrase_count / 8, 1.0)  # 8个短语就满分

    def _check_polite_tone(self, text: str) -> float:
        """检查礼貌语气"""
        polite_words = [
            'please', 'thank you', 'appreciate', 'regards',
            'sincerely', 'best regards', 'kindly', 'would',
            'could', 'respectfully', 'please note', 'we apologize'
        ]

        text_lower = text.lower()
        polite_count = sum(1 for word in polite_words if word in text_lower)

        # 归一化
        return min(polite_count / 6, 1.0)  # 6个词就满分

    def _check_entropy(self, features: Dict[str, Any]) -> float:
        """检查熵值"""
        trad = features.get('traditional', {})
        text_feats = trad.get('text', {})
        entropy = text_feats.get('entropy', 4.5)

        # LLM生成的文本熵值通常在3-5之间
        if 3.0 <= entropy <= 5.0:
            return 1.0
        elif entropy > 5.0:
            return max(0, 1 - (entropy - 5.0) / 3.0)
        else:
            return max(0, entropy / 3.0)

    def _collect_evidence(self, text: str, indicators: Dict[str, float]) -> List[str]:
        """收集证据"""
        evidence = []

        if indicators['perfect_grammar'] > 0.8:
            evidence.append("语法过于完美，无常见错误")

        if indicators['balanced_structure'] > 0.7:
            evidence.append("段落结构高度均衡，疑似人工设计")

        if indicators['generic_phrases'] > 0.3:
            evidence.append("使用大量AI常用短语")

        if indicators['polite_tone'] > 0.6:
            evidence.append("语气过于礼貌和正式")

        if indicators['low_entropy'] > 0.7:
            evidence.append("文本熵值在AI生成范围")

        return evidence

    def _calculate_llm_score(self, indicators: Dict[str, float]) -> float:
        """计算LLM生成评分"""
        weighted_score = 0.0

        for indicator, score in indicators.items():
            weight = self.llm_indicators.get(indicator, 0.0)
            weighted_score += score * weight

        # 降低敏感度，避免误报
        return min(weighted_score * 1.3, 1.0)  # 提高倍数

    def detect_llm_phishing_pattern(self, text: str) -> Dict[str, Any]:
        """检测LLM生成钓鱼邮件的典型模式"""
        patterns = {
            'has_sophisticated_deception': False,
            'has_contextual_awareness': False,
            'has_emotional_manipulation': False,
            'uses_technical_jargon': False,
            'mimics_official_tone': False
        }

        # 精密欺骗
        sophisticated_patterns = [
            r'as part of our.*security',
            r'standard.*procedure.*security',
            r'verify.*your.*information.*protect'
        ]
        patterns['has_sophisticated_deception'] = any(
            re.search(p, text, re.I) for p in sophisticated_patterns
        )

        # 上下文感知
        contextual_patterns = [
            r'recent.*transaction',
            r'your.*account',
            r'unusual.*activity'
        ]
        patterns['has_contextual_awareness'] = any(
            re.search(p, text, re.I) for p in contextual_patterns
        )

        # 情感操纵
        emotional_patterns = [
            r'o protect.*account',
            r'for your.*security',
            r'apologize.*inconvenience'
        ]
        patterns['has_emotional_manipulation'] = any(
            re.search(p, text, re.I) for p in emotional_patterns
        )

        # 技术术语
        technical_patterns = [
            r'encrypted', r'secure.*server', r'authentication',
            r'verification.*process', r'encryption'
        ]
        patterns['uses_technical_jargon'] = any(
            re.search(p, text, re.I) for p in technical_patterns
        )

        # 官方语气
        official_patterns = [
            r'department', r'team', r'division', r'service',
            r'support', r'security.*team'
        ]
        patterns['mimics_official_tone'] = any(
            re.search(p, text, re.I) for p in official_patterns
        )

        return patterns

    def generate_llm_attack_report(
        self,
        llm_result: Dict[str, Any],
        phishing_patterns: Dict[str, Any]
    ) -> str:
        """生成LLM攻击报告"""
        report_lines = [
            "=== LLM生成攻击分析报告 ====\n",
            f"LLM生成可能性: {'高' if llm_result['llm_score'] > 0.6 else '中' if llm_result['llm_score'] > 0.3 else '低'}",
            f"LLM评分: {llm_result['llm_score']:.2f} / 1.00",
            f"置信度: {llm_result['confidence']:.1f}%=\n"
        ]

        if llm_result['evidence']:
            report_lines.append("检测到的LLM生成特征:")
            for i, evidence in enumerate(llm_result['evidence'], 1):
                report_lines.append(f"  {i}. {evidence}")
            report_lines.append("")

        report_lines.append("钓鱼邮件模式分析:")
        for pattern, detected in phishing_patterns.items():
            status = "✓" if detected else "✗"
            report_lines.append(f"  {status} {pattern}")

        return "\n".join(report_lines)
