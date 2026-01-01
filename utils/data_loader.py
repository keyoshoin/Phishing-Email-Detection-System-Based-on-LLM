"""
数据集加载工具
支持多种主流数据集的加载和预处理
"""
import os
import json
import csv
import pandas as pd
from pathlib import Path
from typing import Tuple, List, Dict
import email
from bs4 import BeautifulSoup
import re


class DataLoader:
    """数据集加载器"""

    def __init__(self, data_dir: str = 'data'):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

    def load_from_json(self, filepath: str) -> Tuple[List[str], List[int], List[str]]:
        """
        从JSON文件加载邮件数据
        返回: (邮件内容列表, 标签列表, 类型列表)
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"文件不存在: {filepath}")

        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        texts = [item['content'] for item in data]
        labels = [item.get('label', item.get('is_phishing', 0)) for item in data]
        types = [item.get('type', 'unknown') for item in data]

        return texts, labels, types

    def load_from_csv(self, filepath: str, text_col: str = 'text',
                     label_col: str = 'label') -> Tuple[List[str], List[int]]:
        """
        从CSV文件加载数据
        返回: (邮件内容列表, 标签列表)
        """
        filepath = Path(filepath)
        if not filepath.exists():
            raise FileNotFoundError(f"文件不存在: {filepath}")

        df = pd.read_csv(filepath)
        texts = df[text_col].tolist()
        labels = df[label_col].tolist()

        return texts, labels

    def load_eml_file(self, filepath: str) -> str:
        """
        从.eml文件中提取纯文本内容
        """
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            msg = email.message_from_file(f)

        # 提取邮件内容
        if msg.is_multipart():
            text_parts = []
            for part in msg.walk():
                if part.get_content_type() == 'text/plain':
                    text_parts.append(part.get_payload(decode=True).decode('utf-8', errors='ignore'))
                elif part.get_content_type() == 'text/html':
                    html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                    # 从HTML中提取文本
                    soup = BeautifulSoup(html, 'lxml')
                    text = soup.get_text(separator=' ', strip=True)
                    text_parts.append(text)
            return '\n'.join(text_parts)
        else:
            content = msg.get_payload(decode=True)
            if isinstance(content, bytes):
                return content.decode('utf-8', errors='ignore')
            return str(content)

    def clean_email_text(self, text: str) -> str:
        """
        清理邮件文本
        - 移除多余的空格和换行
        - 移除HTML标签
        - 标准化文本格式
        """
        # 移除HTML标签
        if '<' in text and '>' in text:
            soup = BeautifulSoup(text, 'lxml')
            text = soup.get_text(separator=' ', strip=True)

        # 移除多余的空格和换行
        text = re.sub(r'\s+', ' ', text)
        text = text.strip()

        return text

    def split_dataset(self, texts: List[str], labels: List[int],
                    train_ratio: float = 0.8,
                    val_ratio: float = 0.1,
                    test_ratio: float = 0.1) -> Dict[str, Tuple[List[str], List[int]]]:
        """
        分割数据集为训练集、验证集和测试集
        """
        # 验证比例
        if abs(train_ratio + val_ratio + test_ratio - 1.0) > 0.01:
            raise ValueError("数据集比例之和必须等于1.0")

        # 合并文本和标签
        combined = list(zip(texts, labels))

        # 打乱数据
        import random
        random.shuffle(combined)

        # 计算分割点
        total = len(combined)
        train_end = int(total * train_ratio)
        val_end = train_end + int(total * val_ratio)

        # 分割
        train_data = combined[:train_end]
        val_data = combined[train_end:val_end]
        test_data = combined[val_end:]

        return {
            'train': ( [t[0] for t in train_data], [t[1] for t in train_data] ),
            'val': ( [t[0] for t in val_data], [t[1] for t in val_data] ),
            'test': ( [t[0] for t in test_data], [t[1] for t in test_data] )
        }

    def balance_dataset(self, texts: List[str], labels: List[int],
                     target_samples_per_class: int = None) -> Tuple[List[str], List[int]]:
        """
        平衡数据集（过采样或欠采样）
        """
        from collections import Counter
        import random

        # 统计每个类别的样本数
        label_counts = Counter(labels)

        if target_samples_per_class is None:
            # 使用最大类别数作为目标
            target_samples_per_class = max(label_counts.values())

        balanced_texts = []
        balanced_labels = []

        for label, count in label_counts.items():
            # 获取该类别的所有样本
            class_texts = [t for t, l in zip(texts, labels) if l == label]

            if count < target_samples_per_class:
                # 过采样：随机重复样本
                multiplier = (target_samples_per_class // count) + 1
                class_texts = class_texts * multiplier
                class_texts = class_texts[:target_samples_per_class]
            elif count > target_samples_per_class:
                # 欠采样：随机选择样本
                class_texts = random.sample(class_texts, target_samples_per_class)

            balanced_texts.extend(class_texts)
            balanced_labels.extend([label] * target_samples_per_class)

        # 打乱
        combined = list(zip(balanced_texts, balanced_labels))
        random.shuffle(combined)

        return [t[0] for t in combined], [t[1] for t in combined]

    def generate_statistics(self, texts: List[str], labels: List[int],
                        types: List[str] = None) -> Dict:
        """
        生成数据集统计信息
        """
        from collections import Counter
        import numpy as np

        stats = {
            'total_samples': len(texts),
            'total_phishing': sum(labels),
            'total_normal': len(labels) - sum(labels),
            'phishing_ratio': sum(labels) / len(labels) if labels else 0,
            'avg_length': np.mean([len(t) for t in texts]) if texts else 0,
            'max_length': max([len(t) for t in texts]) if texts else 0,
            'min_length': min([len(t) for t in texts]) if texts else 0,
        }

        if types:
            type_counts = Counter(types)
            stats['type_distribution'] = dict(type_counts)

        return stats

    def save_processed_data(self, texts: List[str], labels: List[int],
                          filepath: str, types: List[str] = None):
        """
        保存处理后的数据为JSON格式
        """
        data = []
        for i, (text, label) in enumerate(zip(texts, labels)):
            item = {
                'id': i,
                'content': text,
                'label': int(label),
                'is_phishing': bool(label)
            }
            if types and i < len(types):
                item['type'] = types[i]
            data.append(item)

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

        print(f"已保存 {len(data)} 条数据到 {filepath}")


# 便捷函数
def load_sample_emails(filepath: str = 'data/sample_emails.json') -> Tuple[List[str], List[int], List[str]]:
    """加载示例邮件数据"""
    loader = DataLoader()
    return loader.load_from_json(filepath)


def create_dataset_splits(texts: List[str], labels: List[int],
                       train_ratio: float = 0.8,
                       val_ratio: float = 0.1) -> Dict:
    """创建数据集划分"""
    loader = DataLoader()
    return loader.split_dataset(texts, labels, train_ratio, val_ratio, 1 - train_ratio - val_ratio)


# Note: To use DataLoader, import it in your application:
# from utils.data_loader import DataLoader
# loader = DataLoader()
