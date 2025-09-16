#!/usr/bin/env python3
"""
YouTube敏感内容审查捕获脚本
专注于提取对敏感词匹配有用的信息
"""
import mitmproxy.http
from mitmproxy import ctx
import json
import datetime
import re
from urllib.parse import urlparse, parse_qs, unquote

class ContentExtractor:
    def __init__(self):
        self.sensitive_patterns = {
            'title': r'"title":"([^"]+)"',
            'description': r'"description":"([^"]+)"',
            'content': r'"content":"([^"]+)"',
            'text': r'"text":"([^"]+)"',
            'message': r'"message":"([^"]+)"',
            'name': r'"name":"([^"]+)"',
            'query': r'q=([^&]+)',  # 搜索查询
        }
    
    def extract_sensitive_content(self, text):
        """提取可能包含敏感信息的文本内容"""
        if not text:
            return {}
        
        extracted_content = {}
        
        for content_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # URL解码并去重
                decoded_matches = []
                for match in matches:
                    try:
                        decoded = unquote(match)
                        if decoded not in decoded_matches:
                            decoded_matches.append(decoded)
                    except:
                        if match not in decoded_matches:
                            decoded_matches.append(match)
                
                if decoded_matches:
                    extracted_content[content_type] = decoded_matches
        
        return extracted_content
    
    def extract_video_info(self, url, headers):
        """从URL和头信息中提取视频相关信息"""
        info = {}
        
        # 从URL提取视频ID
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if 'v' in query_params:
            info['video_id'] = query_params['v'][0]
        if 'docid' in query_params:
            info['video_id'] = query_params['docid'][0]
        
        # 从headers提取用户信息
        if 'x-youtube-client-name' in headers:
            info['client_name'] = headers['x-youtube-client-name']
        if 'x-youtube-client-version' in headers:
            info['client_version'] = headers['x-youtube-client-version']
        
        return info

class YouTubeContentCapture:
    def __init__(self):
        self.num_requests = 0
        self.output_file = "sensitive_content_analysis.txt"
        self.extractor = ContentExtractor()
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("YouTube敏感内容分析日志\n")
            f.write("=" * 50 + "\n")
            f.write(f"开始时间: {datetime.datetime.now()}\n\n")
            f.write("重点关注以下内容进行敏感词匹配：\n")
            f.write("1. 视频标题和描述\n")
            f.write("2. 评论内容\n") 
            f.write("3. 搜索查询\n")
            f.write("4. 用户消息和文本内容\n")
            f.write("=" * 50 + "\n\n")

    def _parse_request(self, flow):
        """解析HTTP请求"""
        request = flow.request
        parsed_url = urlparse(request.url)
        
        request_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "request",
            "method": request.method,
            "url": request.url,
            "host": request.host,
            "path": parsed_url.path,
            "is_youtube": "youtube.com" in request.host or "youtu.be" in request.host
        }
        
        # 提取视频信息
        video_info = self.extractor.extract_video_info(request.url, dict(request.headers))
        if video_info:
            request_info["video_info"] = video_info
        
        # 提取敏感内容
        if request.text:
            sensitive_content = self.extractor.extract_sensitive_content(request.text)
            if sensitive_content:
                request_info["sensitive_content"] = sensitive_content
        
        return request_info

    def _parse_response(self, flow):
        """解析HTTP响应"""
        response = flow.response
        
        response_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "response", 
            "status_code": response.status_code,
            "url": flow.request.url,
            "is_youtube": "youtube.com" in flow.request.host or "youtu.be" in flow.request.host
        }
        
        # 提取敏感内容
        if response.text:
            sensitive_content = self.extractor.extract_sensitive_content(response.text)
            if sensitive_content:
                response_info["sensitive_content"] = sensitive_content
                
                # 记录找到的敏感内容
                ctx.log.info(f"📝 发现 {len(sensitive_content)} 类可审查内容")
                for content_type, contents in sensitive_content.items():
                    ctx.log.info(f"   - {content_type}: {len(contents)} 条")
        
        return response_info

    def _write_to_file(self, data):
        """只写入包含敏感内容的数据"""
        try:
            # 只有当包含敏感内容或视频信息时才写入
            if data.get("sensitive_content") or data.get("video_info"):
                with open(self.output_file, 'a', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
                    f.write(",\n")
        except Exception as e:
            ctx.log.error(f"写入文件时出错: {e}")

    def request(self, flow: mitmproxy.http.HTTPFlow):
        self.num_requests += 1
        
        is_youtube = "youtube.com" in flow.request.host or "youtu.be" in flow.request.host
        if is_youtube:
            ctx.log.info(f"🎥 YouTube请求 #{self.num_requests}: {flow.request.url}")
        
        request_info = self._parse_request(flow)
        self._write_to_file(request_info)

    def response(self, flow: mitmproxy.http.HTTPFlow):
        response_info = self._parse_response(flow)
        self._write_to_file(response_info)
        
        if response_info["is_youtube"] and response_info.get("sensitive_content"):
            content_count = sum(len(v) for v in response_info["sensitive_content"].values())
            ctx.log.info(f"📺 发现 {content_count} 条可审查内容")

# 添加捕获器到mitmproxy
addons = [YouTubeContentCapture()]