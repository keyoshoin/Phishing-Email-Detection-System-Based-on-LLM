"""
测试脚本
用于测试检测系统的功能
"""
import json
from pathlib import Path
from models.detector import get_detector


def load_sample_emails():
    """加载示例邮件"""
    data_file = Path(__file__).parent / 'data' / 'sample_emails.json'
    with open(data_file, 'r', encoding='utf-8') as f:
        emails = json.load(f)
    return emails


def test_single_detection():
    """测试单个邮件检测"""
    print("=" * 60)
    print("测试单个邮件检测")
    print("=" * 60)
    
    detector = get_detector()
    
    # 测试钓鱼邮件
    phishing_email = """
    URGENT: Your account will be suspended!
    
    Click here to verify: http://suspicious-site.tk/verify
    
    Provide your password and credit card immediately!
    """
    
    result = detector.detect(phishing_email)
    
    print(f"\n检测结果: {result['classification']}")
    print(f"风险评分: {result['risk_score']}")
    print(f"风险等级: {result['risk_level']}")
    print(f"置信度: {result['confidence']}%")
    
    if result['suggestions']:
        print("\n安全建议:")
        for i, suggestion in enumerate(result['suggestions'], 1):
            print(f"  {i}. {suggestion}")


def test_batch_detection():
    """测试批量检测"""
    print("\n" + "=" * 60)
    print("测试批量检测")
    print("=" * 60)
    
    detector = get_detector()
    emails = load_sample_emails()
    
    # 提取邮件内容
    email_contents = [email['content'] for email in emails]
    
    # 批量检测
    results = detector.batch_detect(email_contents)
    
    # 统计结果
    correct = 0
    total = len(emails)
    
    print(f"\n检测 {total} 封邮件:")
    print("-" * 60)
    
    for i, (email, result) in enumerate(zip(emails, results), 1):
        actual_label = email['is_phishing']
        predicted = result['is_phishing']
        
        is_correct = actual_label == predicted
        if is_correct:
            correct += 1
        
        status = "✓" if is_correct else "✗"
        print(f"{status} 邮件 {i}: {email['type']}")
        print(f"   实际: {'钓鱼' if actual_label else '正常'} | "
              f"预测: {'钓鱼' if predicted else '正常'} | "
              f"风险: {result['risk_score']}")
    
    accuracy = (correct / total) * 100
    print("-" * 60)
    print(f"\n准确率: {correct}/{total} ({accuracy:.1f}%)")


def test_feature_extraction():
    """测试特征提取"""
    print("\n" + "=" * 60)
    print("测试特征提取")
    print("=" * 60)
    
    detector = get_detector()
    
    test_email = """
    Dear user,
    
    Your account has been suspended. Click here: http://phishing-site.tk/verify
    
    Provide your password, credit card, and SSN immediately!
    
    This is URGENT! Act now or lose your account forever!!!
    """
    
    features = detector.feature_extractor.extract_features(test_email)
    
    print("\n提取的特征:")
    print("-" * 60)
    
    # 传统特征
    trad = features['traditional']
    
    print("\nURL特征:")
    print(f"  URL数量: {trad['url']['url_count']}")
    print(f"  可疑URL数量: {trad['url']['suspicious_url_count']}")
    
    print("\n关键词特征:")
    print(f"  钓鱼关键词数: {trad['keyword']['phishing_keyword_count']}")
    print(f"  紧急语言: {trad['keyword']['has_urgent_language']}")
    print(f"  要求个人信息: {trad['keyword']['has_personal_info_request']}")
    
    print("\n文本特征:")
    print(f"  文本长度: {trad['text']['length']}")
    print(f"  单词数: {trad['text']['word_count']}")
    print(f"  感叹号数: {trad['text']['exclamation_count']}")


def test_report_generation():
    """测试报告生成"""
    print("\n" + "=" * 60)
    print("测试报告生成")
    print("=" * 60)
    
    detector = get_detector()
    
    test_email = """
    URGENT SECURITY ALERT!
    
    Your PayPal account will be closed in 24 hours!
    
    Click here to verify: http://paypal-fake.tk/login
    
    Enter your password and credit card to restore access!
    """
    
    report = detector.generate_report(test_email)
    print("\n" + report)


def test_model_training():
    """测试模型训练"""
    print("\n" + "=" * 60)
    print("测试模型训练")
    print("=" * 60)
    
    detector = get_detector()
    emails = load_sample_emails()
    
    # 准备训练数据
    texts = [email['content'] for email in emails]
    labels = [email['label'] for email in emails]
    
    print(f"\n训练样本数: {len(texts)}")
    print(f"钓鱼邮件: {sum(labels)}")
    print(f"正常邮件: {len(labels) - sum(labels)}")
    
    # 训练模型
    try:
        detector.train(texts, labels)
        print("\n模型训练成功！")
    except Exception as e:
        print(f"\n模型训练失败: {e}")
        print("这可能是因为样本数量太少或缺少依赖库")


def run_all_tests():
    """运行所有测试"""
    print("\n")
    print("*" * 60)
    print("钓鱼邮件检测系统 - 测试套件")
    print("*" * 60)
    
    try:
        test_single_detection()
        test_batch_detection()
        test_feature_extraction()
        test_report_generation()
        # test_model_training()  # 注释掉以避免每次都训练
        
        print("\n" + "*" * 60)
        print("所有测试完成!")
        print("*" * 60)
        
    except Exception as e:
        print(f"\n测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    run_all_tests()
