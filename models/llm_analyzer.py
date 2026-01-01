"""
LLM分析器
使用大语言模型进行高级分析和建议生成
"""
import re
from typing import Dict, List, Any
import warnings
warnings.filterwarnings('ignore')

from config import USE_OPENAI, OPENAI_API_KEY, OPENAI_MODEL

# 尝试导入OpenAI
try:
    import openai
    openai.api_key = OPENAI_API_KEY
    OPENAI_AVAILABLE = USE_OPENAI and OPENAI_API_KEY
except ImportError:
    OPENAI_AVAILABLE = False


class LLMAnalyzer:
    """LLM分析器"""
    
    def __init__(self):
        self.use_openai = OPENAI_AVAILABLE
    
    def analyze_with_gpt(self, text: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """使用GPT进行分析"""
        if not self.use_openai:
            return self._rule_based_analysis(text, features)
        
        try:
            # 准备prompt
            prompt = self._prepare_prompt(text, features)
            
            # 调用GPT
            response = openai.ChatCompletion.create(
                model=OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "你是一个专业的网络安全分析师，擅长识别钓鱼邮件。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=500
            )
            
            result = response.choices[0].message.content
            return self._parse_gpt_response(result)
            
        except Exception as e:
            print(f"GPT分析失败: {e}")
            return self._rule_based_analysis(text, features)
    
    def _prepare_prompt(self, text: str, features: Dict[str, Any]) -> str:
        """准备GPT prompt"""
        # 限制文本长度
        text_preview = text[:500] + "..." if len(text) > 500 else text
        
        # 提取关键特征
        trad = features.get('traditional', {})
        url_count = trad.get('url', {}).get('url_count', 0)
        suspicious_urls = trad.get('url', {}).get('suspicious_url_count', 0)
        keywords = trad.get('keyword', {}).get('phishing_keywords', [])
        
        prompt = f"""
请分析以下邮件是否为钓鱼邮件：

邮件内容预览：
{text_preview}

检测到的特征：
- URL数量: {url_count}
- 可疑URL数量: {suspicious_urls}
- 钓鱼关键词: {', '.join(keywords[:5])}

请从以下角度分析：
1. 这是否为钓鱼邮件？
2. 风险评分（0-100）
3. 主要风险点
4. 给用户的建议

请用JSON格式回复：
{{
    "is_phishing": true/false,
    "confidence": 0-100,
    "risk_points": ["风险点1", "风险点2"],
    "suggestions": ["建议1", "建议2"]
}}
"""
        return prompt
    
    def _parse_gpt_response(self, response: str) -> Dict[str, Any]:
        """解析GPT响应"""
        try:
            import json
            # 尝试提取JSON
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                result = json.loads(json_match.group())
                return result
        except:
            pass
        
        # 解析失败，使用规则
        return {
            'is_phishing': 'phishing' in response.lower() or '钓鱼' in response,
            'confidence': 70,
            'risk_points': ['需要人工审核'],
            'suggestions': ['建议谨慎处理此邮件']
        }
    
    def _rule_based_analysis(self, text: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """基于规则的分析（当GPT不可用时）"""
        risk_points = []
        suggestions = []
        confidence = 50
        
        trad = features.get('traditional', {})
        
        # 分析URL
        url_feats = trad.get('url', {})
        if url_feats.get('suspicious_url_count', 0) > 0:
            risk_points.append(f"包含 {url_feats['suspicious_url_count']} 个可疑链接")
            suggestions.append("不要点击邮件中的任何链接")
            confidence += 20
        
        if url_feats.get('has_ip_url'):
            risk_points.append("包含IP地址形式的URL（非常可疑）")
            confidence += 15
        
        # 分析关键词
        keyword_feats = trad.get('keyword', {})
        keyword_count = keyword_feats.get('phishing_keyword_count', 0)
        if keyword_count > 3:
            risk_points.append(f"包含 {keyword_count} 个钓鱼常见关键词")
            confidence += 10
        
        if keyword_feats.get('has_urgent_language'):
            risk_points.append("使用紧急/威胁性语言")
            suggestions.append("正规机构不会使用威胁性语言要求立即行动")
            confidence += 10
        
        if keyword_feats.get('has_personal_info_request'):
            risk_points.append("要求提供个人敏感信息")
            suggestions.append("永远不要通过邮件提供密码或信用卡信息")
            confidence += 15
        
        # 分析HTML
        html_feats = trad.get('html', {})
        if html_feats.get('hidden_elements', 0) > 0:
            risk_points.append("包含隐藏元素")
            confidence += 10
        
        if html_feats.get('form_count', 0) > 0:
            risk_points.append("包含表单（可能用于窃取信息）")
            suggestions.append("不要在邮件中的表单里输入任何信息")
            confidence += 10
        
        # 通用建议
        if not suggestions:
            suggestions.append("验证发件人身份")
            suggestions.append("直接访问官方网站而非点击链接")
        
        if not risk_points:
            risk_points.append("未发现明显风险特征")
            confidence = 30
        
        is_phishing = confidence > 60
        
        return {
            'is_phishing': is_phishing,
            'confidence': min(confidence, 95),
            'risk_points': risk_points,
            'suggestions': suggestions
        }
    
    def generate_report(self, text: str, features: Dict[str, Any], detection_result: Dict[str, Any]) -> str:
        """生成详细报告"""
        analysis = self.analyze_with_gpt(text, features)
        
        report_lines = [
            "=== 钓鱼邮件检测报告 ===\n",
            f"检测结果: {detection_result.get('classification', '未知')}",
            f"风险评分: {detection_result.get('risk_score', 0)}/100",
            f"置信度: {detection_result.get('confidence', 0)}%",
            f"\n风险等级: {detection_result.get('risk_level', '未知')}\n",
        ]
        
        # 添加风险点
        if analysis.get('risk_points'):
            report_lines.append("\n主要风险点:")
            for i, point in enumerate(analysis['risk_points'], 1):
                report_lines.append(f"  {i}. {point}")
        
        # 添加建议
        if analysis.get('suggestions'):
            report_lines.append("\n安全建议:")
            for i, suggestion in enumerate(analysis['suggestions'], 1):
                report_lines.append(f"  {i}. {suggestion}")
        
        # 添加特征摘要
        trad = features.get('traditional', {})
        report_lines.extend([
            "\n\n特征摘要:",
            f"  - URL数量: {trad.get('url', {}).get('url_count', 0)}",
            f"  - 可疑URL: {trad.get('url', {}).get('suspicious_url_count', 0)}",
            f"  - 钓鱼关键词: {trad.get('keyword', {}).get('phishing_keyword_count', 0)}",
            f"  - 邮件长度: {trad.get('text', {}).get('length', 0)} 字符",
        ])
        
        return "\n".join(report_lines)
