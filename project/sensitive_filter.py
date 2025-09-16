#!/usr/bin/env python3
"""
敏感词审查模块
使用Aho-Corasick算法进行高效模式匹配
"""
import ahocorasick
import os
import re
from typing import Dict, List, Any

# 全局敏感度阈值
SENSITIVITY_THRESHOLD = 3

def set_sensitivity_threshold(threshold):
    """设置敏感度阈值"""
    global SENSITIVITY_THRESHOLD
    if isinstance(threshold, int) and threshold >= 0:
        SENSITIVITY_THRESHOLD = threshold
        print(f"✅ 敏感度阈值已设置为: {threshold}")
    else:
        print(f"❌ 无效的阈值: {threshold}，必须是非负整数")

def get_sensitivity_threshold():
    """获取当前敏感度阈值"""
    return SENSITIVITY_THRESHOLD

class SensitiveFilter:
    def __init__(self, word_file_path="sensitive_words.txt"):
        """
        初始化敏感词过滤器
        :param word_file_path: 敏感词文件路径
        """
        self.automaton = ahocorasick.Automaton()
        self.total_matches = 0
        self._load_sensitive_words(word_file_path)
    
    def _load_sensitive_words(self, file_path):
        """从文件加载敏感词"""
        if not os.path.exists(file_path):
            # 创建默认的敏感词文件示例
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write("# 敏感词列表（每行一个或多个用空格分隔）\n")
                f.write("敏感词1 敏感词2 敏感词3\n")
                f.write("测试敏感词\n")
                f.write("违规内容\n")
            print(f"⚠️  敏感词文件不存在，已创建示例文件: {file_path}")
        
        sensitive_words = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释
                    words = line.split()
                    sensitive_words.extend(words)
        
        for word in sensitive_words:
            if word:  # 确保不是空字符串
                self.automaton.add_word(word, word)
        
        self.automaton.make_automaton()
        print(f"✅ 加载 {len(sensitive_words)} 个敏感词: {sensitive_words[:10]}{'...' if len(sensitive_words) > 10 else ''}")
        print(f"✅ 当前敏感度阈值: {get_sensitivity_threshold()}")
    
    def count_matches(self, text: str) -> int:
        """
        统计文本中敏感词匹配次数
        :param text: 待检测文本
        :return: 匹配次数
        """
        if not text or not isinstance(text, str):
            return 0
        
        count = 0
        for end_index, original_value in self.automaton.iter(text):
            count += 1
            # 调试输出
            start_index = end_index - len(original_value) + 1
            matched_word = text[start_index:end_index + 1]
            print(f"🔍 匹配敏感词: '{matched_word}' at position {start_index}-{end_index}")
            print(f"   上下文: ...{text[max(0, start_index-10):start_index]}【{matched_word}】{text[end_index+1:min(len(text), end_index+11)]}...")
        
        if count > 0:
            print(f"✅ 在文本中发现 {count} 个敏感词匹配")
        
        return count
    
    def filter_content(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        审查数据内容并返回匹配次数
        :param data: 包含各种内容的数据字典
        :return: 包含审查结果的数据字典
        """
        total_matches = 0
        content_fields = self._get_content_fields(data)
    
        print(f"🔍 审查数据，找到 {len(content_fields)} 个内容字段")
    
        # 如果没有找到内容字段，显示数据结构用于调试
        if len(content_fields) == 0:
            print("⚠️  没有找到内容字段，数据结构可能是:")
            print(f"   数据类型: {type(data)}")
            if isinstance(data, dict):
                print(f"   字典键: {list(data.keys())}")
                if "extracted_content" in data:
                    print(f"   extracted_content类型: {type(data['extracted_content'])}")
                    if isinstance(data['extracted_content'], dict):
                        print(f"   extracted_content键: {list(data['extracted_content'].keys())}")
    
        # 打印所有找到的内容字段
        for field_path, content in content_fields:
            print(f"   📝 字段: {field_path}")
            print(f"     内容: {content[:100]}...")
    
        # 统计所有内容字段的匹配次数
        for field_path, content in content_fields:
            if isinstance(content, str):
                print(f"🔎 检查字段: {field_path}")
                matches = self.count_matches(content)
                total_matches += matches
                if matches > 0:
                    self._add_match_info(data, field_path, matches, content)
                    print(f"🚨 字段 {field_path} 发现 {matches} 个敏感词匹配")
    
        # 添加审查结果信息
        threshold = get_sensitivity_threshold()
        data["sensitive_check"] = {
            "total_matches": total_matches,
            "is_sensitive": total_matches >= threshold,
            "checked_fields": len(content_fields),
            "threshold": threshold
        }
    
        self.total_matches += total_matches
    
        return data
    
    def _get_content_fields(self, data: Dict, base_path: str = "") -> List:
        """
        递归获取所有可能包含文本内容的字段
        :param data: 数据字典
        :param base_path: 当前路径
        :return: 内容字段列表 [(路径, 内容)]
        """
        content_fields = []
    
        # 定义需要检查的内容字段模式
        content_patterns = {
            'title', 'description', 'content', 'text', 
            'message', 'name', 'query', 'comment',
            'caption', 'transcript', 'summary', 'label',
            'snippet', 'display', 'simpleText', 'accessibility',
            'shortDescription', 'ownerChannelName', 'qualityLabel',
            'contextParams', 'contentLength'  # 添加YouTube特有字段
        }
    
        # 首先检查 extracted_content 字段（来自youtube_proxy的提取结果）
        if "extracted_content" in data and isinstance(data["extracted_content"], dict):
            for key, values in data["extracted_content"].items():
                if any(pattern in key.lower() for pattern in content_patterns):
                    if isinstance(values, list):
                        for i, value in enumerate(values):
                            if isinstance(value, str) and value.strip():
                                field_path = f"extracted_content.{key}[{i}]"
                                content_fields.append((field_path, value))
                                print(f"🔍 找到内容字段: {field_path} = {value[:50]}...")
    
        # 然后递归检查其他嵌套结构
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{base_path}.{key}" if base_path else key
            
                # 跳过已经处理过的extracted_content
                if key == "extracted_content":
                    continue
                
                # 如果字段名包含内容关键词，且值是字符串
                if (isinstance(key, str) and 
                    any(pattern in key.lower() for pattern in content_patterns) and 
                    isinstance(value, str) and value.strip()):
                    content_fields.append((current_path, value))
                    print(f"🔍 找到内容字段: {current_path} = {value[:50]}...")
            
                # 如果是字典或列表，递归检查
                if isinstance(value, (dict, list)):
                    content_fields.extend(self._get_content_fields(value, current_path))
    
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{base_path}[{i}]" if base_path else f"[{i}]"
                if isinstance(item, (dict, list)):
                    content_fields.extend(self._get_content_fields(item, current_path))
    
        return content_fields
    
    def _add_match_info(self, data: Dict, field_path: str, matches: int, content: str):
        """
        添加匹配信息到数据中
        :param data: 原始数据
        :param field_path: 字段路径
        :param matches: 匹配次数
        :param content: 原始内容
        """
        if "sensitive_matches" not in data:
            data["sensitive_matches"] = []
        
        data["sensitive_matches"].append({
            "field": field_path,
            "matches": matches,
            "content_sample": content[:100] + "..." if len(content) > 100 else content
        })
    
    def replace_sensitive_content(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        替换敏感内容为占位符（保持数据结构不变）
        :param data: 原始数据
        :return: 替换后的数据
        """
        def _recursive_replace(obj, path=""):
            if isinstance(obj, dict):
                result = {}
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    result[key] = _recursive_replace(value, current_path)
                return result
            elif isinstance(obj, list):
                return [_recursive_replace(item, f"{path}[{i}]") for i, item in enumerate(obj)]
            elif isinstance(obj, str):
                # 检查字段路径是否包含内容关键词
                content_patterns = {'title', 'description', 'content', 'text', 'message', 'name'}
                if any(pattern in path.lower() for pattern in content_patterns):
                    return "⚠️ 该内容已被过滤"
                return obj
            else:
                return obj
        
        return _recursive_replace(data)

# 创建全局过滤器实例
sensitive_filter = SensitiveFilter()

def check_and_filter_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    审查并过滤数据的公共接口
    :param data: 输入数据
    :return: 处理后的数据
    """
    # 首先进行敏感词检测
    checked_data = sensitive_filter.filter_content(data)
    
    # 如果敏感匹配次数 >= 阈值，替换所有内容
    threshold = get_sensitivity_threshold()
    if checked_data.get("sensitive_check", {}).get("is_sensitive", False):
        print(f"🚨 检测到敏感内容，匹配次数: {checked_data['sensitive_check']['total_matches']} (阈值: {threshold})")
        filtered_data = sensitive_filter.replace_sensitive_content(checked_data)
        filtered_data["sensitive_check"]["action_taken"] = "content_replaced"
        return filtered_data
    
    checked_data["sensitive_check"]["action_taken"] = "passed"
    return checked_data

def get_filter_stats() -> Dict[str, Any]:
    """获取过滤器统计信息"""
    return {
        "total_matches": sensitive_filter.total_matches,
        "automaton_size": len(sensitive_filter.automaton),
        "sensitivity_threshold": get_sensitivity_threshold()
    }

# 测试函数
def test_sensitive_filter():
    """测试敏感词检测功能"""
    print("🧪 测试敏感词检测功能...")
    
    # 测试不同阈值
    test_thresholds = [1, 3, 5]
    
    for threshold in test_thresholds:
        print(f"\n🔧 测试阈值: {threshold}")
        set_sensitivity_threshold(threshold)
        
        filter = SensitiveFilter("sensitive_words.txt")
        
        # 测试文本
        test_text = "这是一个包含敏感词和测试敏感词的文本"
        
        matches = filter.count_matches(test_text)
        print(f"文本: '{test_text}' -> 匹配次数: {matches}")
        print(f"是否敏感: {matches >= threshold}")

def test_with_actual_content():
    """使用实际内容测试"""
    print("🧪 使用实际YouTube内容测试敏感词检测...")
    
    # 设置阈值为1
    set_sensitivity_threshold(1)
    
    filter = SensitiveFilter("sensitive_words.txt")
    
    # 模拟YouTube响应数据
    test_data = {
        "title": "九三阅兵背后，这4个故事读懂中国军人 | CCTV「面对面」",
        "shortDescription": "2025年9月3日，纪念中国人民抗日战争暨世界反法西斯战争胜利80周年阅兵式在天安门广场隆重举行。",
        "simpleText": "九三阅兵背后，这4个故事读懂中国军人 | CCTV「面对面」",
        "ownerChannelName": "CCTV中国中央电视台"
    }
    
    print("📋 测试数据:")
    for key, value in test_data.items():
        print(f"   {key}: {value}")
    
    # 测试单个字段
    print("\n🔎 测试单个字段:")
    content = test_data["shortDescription"]
    matches = filter.count_matches(content)
    print(f"   shortDescription 匹配次数: {matches}")
    
    # 测试完整数据结构
    print("\n🔎 测试完整数据结构:")
    result = filter.filter_content(test_data)
    print(f"   总匹配次数: {result.get('sensitive_check', {}).get('total_matches', 0)}")
    print(f"   是否敏感: {result.get('sensitive_check', {}).get('is_sensitive', False)}")
    
    if result.get('sensitive_matches'):
        for match in result['sensitive_matches']:
            print(f"   🚨 匹配: {match['field']} - {match['matches']}次")

if __name__ == "__main__":
    test_with_actual_content()