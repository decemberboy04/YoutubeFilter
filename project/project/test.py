#!/usr/bin/env python3
"""测试修复后的敏感词检测"""
from sensitive_filter import SensitiveFilter, set_sensitivity_threshold

def test_youtube_data_structure():
    """测试YouTube数据结构"""
    print("🧪 测试YouTube数据结构处理...")
    
    set_sensitivity_threshold(1)
    filter = SensitiveFilter("sensitive_words.txt")
    
    # 模拟YouTube代理返回的数据结构
    test_data = {
        "timestamp": "2024-01-01T00:00:00",
        "type": "response",
        "status_code": 200,
        "url": "https://www.youtube.com/watch?v=test",
        "extracted_content": {
            "title": ["九三阅兵背后，这4个故事读懂中国军人 | CCTV「面对面」"],
            "shortDescription": ["2025年9月3日，纪念中国人民抗日战争暨世界反法西斯战争胜利80周年阅兵式在天安门广场隆重举行。"],
            "simpleText": ["九三阅兵背后，这4个故事读懂中国军人 | CCTV「面对面」", "2025年9月3日，纪念中国人民抗日战争..."],
            "ownerChannelName": ["CCTV中国中央电视台"]
        }
    }
    
    print("📋 测试数据:")
    print(f"  包含 extracted_content: {'extracted_content' in test_data}")
    print(f"  extracted_content键: {list(test_data['extracted_content'].keys())}")
    
    result = filter.filter_content(test_data)
    print(f"✅ 找到内容字段: {result['sensitive_check']['checked_fields']}")
    print(f"✅ 总匹配次数: {result['sensitive_check']['total_matches']}")
    print(f"✅ 是否敏感: {result['sensitive_check']['is_sensitive']}")
    
    if result.get('sensitive_matches'):
        for match in result['sensitive_matches']:
            print(f"   🚨 匹配: {match['field']} - {match['matches']}次")

if __name__ == "__main__":
    test_youtube_data_structure()