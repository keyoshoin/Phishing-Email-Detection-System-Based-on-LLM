"""
混合攻击链检测器
专门检测多阶段混合攻击
"""
import re
from typing import Dict, List, Any, Tuple
from collections import defaultdict


class HybridAttackDetector:
    """混合攻击链检测器"""

    def __init__(self):
        # 攻击链阶段映射
        self.attack_chain_stages = {
            'reconnaissance': ['调查', '侦察', 'information gathering'],
            'delivery': ['投递', '钓鱼', '邮件'],
            'exploitation': ['利用', '漏洞', '恶意链接'],
            'installation': ['安装', '下载', '执行'],
            'command_control': ['命令控制', 'C2', '远程'],
            'actions': ['行动', '窃取', '加密', '破坏']
        }

        # 多阶段攻击模式
        self.multi_stage_patterns = [
            # 阶段1: 初始诱饵 -> 阶段2: 诱导点击
            (r'(verification|update|security)', r'(click|visit|link)', '建立信任-诱导操作'),

            # 阶段1: 紧急通知 -> 阶段2: 要求操作
            (r'(urgent|immediate|deadline|alert)', r'(verify|confirm|login)', '紧急威胁-要求操作'),

            # 阶段1: 建立信任 -> 阶段2: 索要信息
            (r'(bank|company|official|service)', r'(password|card|ssn|information)', '官方伪装-索要信息'),

            # 阶段1: 制造问题 -> 阶段2: 提供解决方案
            (r'(suspended|limited|locked|blocked)', r'(click|visit|restore|verify)', '问题-解决方案'),

            # 多阶段关键词
            (r'(step\s*\d+|stage\s*\d+)', r'.*', '明确多阶段')
        ]

    def detect_attack_chain(self, text: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """检测攻击链"""
        attack_chain = {
            'is_hybrid_attack': False,
            'stages_detected': [],
            'stage_count': 0,
            'attack_pattern': None,
            'confidence': 0.0,
            'risk_level': 'low'
        }

        # 1. 检测攻击阶段
        stages = self._detect_attack_stages(text)
        attack_chain['stages_detected'] = stages
        attack_chain['stage_count'] = len(stages)

        # 2. 检测多阶段模式
        pattern_match = self._detect_multi_stage_patterns(text)
        attack_chain['attack_pattern'] = pattern_match

        # 3. 分析攻击链完整性
        is_complete_chain = self._is_complete_attack_chain(stages)
        attack_chain['is_complete_chain'] = is_complete_chain

        # 4. 评估混合攻击可能性
        hybrid_score = self._calculate_hybrid_attack_score(
            stages, pattern_match, features
        )
        attack_chain['hybrid_score'] = hybrid_score
        attack_chain['is_hybrid_attack'] = hybrid_score > 0.45  # 降低阈值
        attack_chain['confidence'] = hybrid_score * 100

        # 5. 确定风险等级
        if hybrid_score > 0.8:
            attack_chain['risk_level'] = 'high'
        elif hybrid_score > 0.6:
            attack_chain['risk_level'] = 'medium'
        else:
            attack_chain['risk_level'] = 'low'

        return attack_chain

    def _detect_attack_stages(self, text: str) -> List[str]:
        """检测攻击阶段"""
        text_lower = text.lower()
        stages_detected = []

        for stage, keywords in self.attack_chain_stages.items():
            for keyword in keywords:
                if keyword in text_lower:
                    if stage not in stages_detected:
                        stages_detected.append(stage)
                    break

        return stages_detected

    def _detect_multi_stage_patterns(self, text: str) -> List[Dict[str, Any]]:
        """检测多阶段模式"""
        patterns_found = []

        for i, pattern in enumerate(self.multi_stage_patterns):
            if len(pattern) == 2:
                stage1_pattern, stage2_pattern = pattern
                match1 = re.search(stage1_pattern, text, re.I)
                match2 = re.search(stage2_pattern, text, re.I)

                if match1 and match2:
                    patterns_found.append({
                        'pattern_id': i,
                        'stage1': match1.group(),
                        'stage2': match2.group(),
                        'distance': abs(match2.start() - match1.end()),
                        'type': 'two_stage'
                    })
            elif len(pattern) == 3:
                stage1_pattern, stage2_pattern, pattern_type = pattern
                match1 = re.search(stage1_pattern, text, re.I)
                match2 = re.search(stage2_pattern, text, re.I)

                if match1 and match2:
                    patterns_found.append({
                        'pattern_id': i,
                        'stage1': match1.group(),
                        'stage2': match2.group(),
                        'distance': abs(match2.start() - match1.end()),
                        'type': pattern_type
                    })

        return patterns_found

    def _is_complete_attack_chain(self, stages: List[str]) -> bool:
        """判断是否为完整的攻击链"""
        # 完整攻击链至少包含3个阶段
        return len(stages) >= 3

    def _calculate_hybrid_attack_score(
        self,
        stages: List[str],
        patterns: List[Dict[str, Any]],
        features: Dict[str, Any]
    ) -> float:
        """计算混合攻击评分"""
        score = 0.0

        # 阶段数量评分 (0-30分)
        stage_score = min(len(stages) * 15, 30)
        score += stage_score

        # 模式匹配评分 (0-40分)
        pattern_score = min(len(patterns) * 20, 40)
        score += pattern_score

        # 特征一致性评分 (0-30分)
        trad = features.get('traditional', {})
        url_feats = trad.get('url', {})
        keyword_feats = trad.get('keyword', {})

        feature_score = 0
        if url_feats.get('url_count', 0) > 0:
            feature_score += 5
        if keyword_feats.get('phishing_keyword_count', 0) > 2:
            feature_score += 10
        if keyword_feats.get('has_urgent_language'):
            feature_score += 8
        if keyword_feats.get('has_personal_info_request'):
            feature_score += 7
        score += feature_score

        # 归一化到0-1
        return min(score / 100.0, 1.0)

    def generate_attack_chain_report(self, attack_chain: Dict[str, Any]) -> str:
        """生成攻击链报告"""
        report_lines = [
            "=== 混合攻击链分析报告 ===\n",
            f"检测到混合攻击: {'是' if attack_chain['is_hybrid_attack'] else '否'}",
            f"攻击链完整度: {'完整' if attack_chain.get('is_complete_chain', False) else '不完整'}",
            f"检测到的阶段数: {attack_chain['stage_count']}",
            f"置信度: {attack_chain['confidence']:.1f}%\n"
        ]

        if attack_chain['stages_detected']:
            report_lines.append("检测到的攻击阶段:")
            for stage in attack_chain['stages_detected']:
                report_lines.append(f"  - {stage}")
            report_lines.append("")

        if attack_chain['attack_pattern']:
            report_lines.append("多阶段攻击模式:")
            for pattern in attack_chain['attack_pattern']:
                report_lines.append(
                    f"  模式{pattern['pattern_id']}: "
                    f"'{pattern['stage1']}' -> '{pattern['stage2']}'"
                )
            report_lines.append("")

        risk_desc = {
            'high': '高风险 - 疑似精心策划的混合攻击链',
            'medium': '中风险 - 可能包含多阶段攻击元素',
            'low': '低风险 - 未检测到明显混合攻击特征'
        }
        report_lines.append(f"风险等级: {attack_chain['risk_level']}")
        report_lines.append(risk_desc[attack_chain['risk_level']])

        return "\n".join(report_lines)
