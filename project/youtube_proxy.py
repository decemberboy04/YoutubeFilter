#!/usr/bin/env python3
"""
YouTube敏感内容审查代理
集成敏感词检测和内容过滤功能
"""
import mitmproxy.http
from mitmproxy import ctx
import json
import datetime
import re
import os
from urllib.parse import urlparse, parse_qs, unquote

# 导入敏感词审查模块
from sensitive_filter import check_and_filter_data, get_filter_stats, set_sensitivity_threshold, \
    get_sensitivity_threshold, sensitive_filter


class ContentExtractor:
    def __init__(self):
        self.content_fields = {
            'title', 'description', 'content', 'text',
            'message', 'name', 'query', 'comment',
            'caption', 'transcript', 'summary', 'label',
            'snippet', 'display', 'simpleText', 'accessibility',
            'shortDescription', 'ownerChannelName', 'qualityLabel'
        }

    def extract_content(self, text):
        """使用JSON解析和正则表达式结合提取内容"""
        if not text:
            return {}

        extracted_content = {}

        try:
            # 首先尝试解析为JSON
            data = json.loads(text)
            ctx.log.info("✅ 成功解析JSON，开始提取内容字段...")
            extracted_content = self._extract_from_json(data)
        except json.JSONDecodeError:
            # 如果不是JSON，使用正则表达式提取
            ctx.log.info("响应不是JSON格式，使用正则表达式提取内容")
            extracted_content = self._extract_with_regex(text)
        except Exception as e:
            ctx.log.error(f"JSON解析错误: {e}")
            extracted_content = self._extract_with_regex(text)

        ctx.log.info(f"📊 总共提取到 {len(extracted_content)} 个内容字段")
        return extracted_content

    def _extract_from_json(self, data, path=""):
        """递归从JSON中提取内容字段"""
        result = {}

        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key

                # 检查是否是内容字段
                if (isinstance(key, str) and
                        any(pattern in key.lower() for pattern in self.content_fields) and
                        isinstance(value, str) and value.strip()):

                    if key not in result:
                        result[key] = []
                    result[key].append(value)
                    ctx.log.info(f"📝 提取字段: {key} = {value[:50]}...")

                # 递归检查嵌套结构
                if isinstance(value, (dict, list)):
                    nested_result = self._extract_from_json(value, current_path)
                    # 合并嵌套结果
                    for nested_key, nested_values in nested_result.items():
                        if nested_key not in result:
                            result[nested_key] = []
                        result[nested_key].extend(nested_values)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]" if path else f"[{i}]"
                if isinstance(item, (dict, list)):
                    nested_result = self._extract_from_json(item, current_path)
                    # 合并嵌套结果
                    for nested_key, nested_values in nested_result.items():
                        if nested_key not in result:
                            result[nested_key] = []
                        result[nested_key].extend(nested_values)

        return result

    def _extract_with_regex(self, text):
        """使用正则表达式提取内容"""
        extracted_content = {}
        patterns = {
            'title': r'"title"\s*:\s*"([^"]+)"',
            'description': r'"description"\s*:\s*"([^"]+)"',
            'content': r'"content"\s*:\s*"([^"]+)"',
            'text': r'"text"\s*:\s*"([^"]+)"',
            'message': r'"message"\s*:\s*"([^"]+)"',
            'name': r'"name"\s*:\s*"([^"]+)"',
            'query': r'q=([^&]+)',
        }

        for content_type, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                decoded_matches = []
                for match in matches:
                    try:
                        # 处理Unicode转义序列
                        decoded = bytes(match, 'utf-8').decode('unicode_escape')
                        if decoded not in decoded_matches:
                            decoded_matches.append(decoded)
                    except:
                        if match not in decoded_matches:
                            decoded_matches.append(match)

                if decoded_matches:
                    extracted_content[content_type] = decoded_matches
                    ctx.log.debug(f"📝 正则提取: {content_type} = {decoded_matches[0][:50]}...")

        return extracted_content

    def extract_video_info(self, url, headers):
        """提取视频信息"""
        info = {}

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        if 'v' in query_params:
            info['video_id'] = query_params['v'][0]
        if 'docid' in query_params:
            info['video_id'] = query_params['docid'][0]

        if 'x-youtube-client-name' in headers:
            info['client_name'] = headers['x-youtube-client-name']
        if 'x-youtube-client-version' in headers:
            info['client_version'] = headers['x-youtube-client-version']

        return info


class YouTubeContentCapture:
    def __init__(self):
        self.num_requests = 0
        self.output_file = "sensitive_content_analysis.txt"
        self.filtered_file = "filtered.txt"
        self.config_file = "proxy_config.json"
        self.extractor = ContentExtractor()
        self.stats = {
            "total_requests": 0,
            "youtube_requests": 0,
            "sensitive_blocks": 0,
            "start_time": datetime.datetime.now().isoformat()
        }

        # 加载配置
        self._load_config()

        # 初始化输出文件
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write("YouTube敏感内容审查日志\n")
            f.write("=" * 50 + "\n")
            f.write(f"开始时间: {self.stats['start_time']}\n\n")
            f.write(f"审查策略: 敏感词匹配次数 >= {get_sensitivity_threshold()} 时拦截内容\n")
            f.write("=" * 50 + "\n\n")

        # 初始化被拦截内容文件
        with open(self.filtered_file, 'w', encoding='utf-8') as f:
            f.write("被拦截内容记录\n")
            f.write("=" * 50 + "\n")
            f.write(f"开始时间: {self.stats['start_time']}\n\n")
            f.write(f"敏感度阈值: {get_sensitivity_threshold()}\n")
            f.write("格式: {时间戳, URL, 匹配次数, 敏感词详情}\n")
            f.write("=" * 50 + "\n\n")

        ctx.log.info(f"✅ 代理启动完成，当前敏感度阈值: {get_sensitivity_threshold()}")

    def _load_config(self):
        """加载配置文件"""
        default_config = {
            "sensitivity_threshold": 3,
            "log_level": "info"
        }

        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    threshold = config.get("sensitivity_threshold", 3)
                    set_sensitivity_threshold(threshold)
                    ctx.log.info(f"📋 从配置文件加载敏感度阈值: {threshold}")
            else:
                # 创建默认配置文件
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(default_config, f, indent=2)
                set_sensitivity_threshold(3)
                ctx.log.info("📋 创建默认配置文件")

        except Exception as e:
            ctx.log.error(f"加载配置文件失败: {e}")
            set_sensitivity_threshold(3)

    def _save_config(self):
        """保存配置到文件"""
        try:
            config = {
                "sensitivity_threshold": get_sensitivity_threshold(),
                "log_level": "info"
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            ctx.log.error(f"保存配置文件失败: {e}")

    def _write_to_file(self, data, filename=None):
        """写入数据到文件"""
        if filename is None:
            filename = self.output_file

        try:
            with open(filename, 'a', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write(",\n")
        except Exception as e:
            ctx.log.error(f"写入文件 {filename} 时出错: {e}")

    def _log_filtered_content(self, flow, checked_data, data_type):
        """记录被拦截的内容到单独文件"""
        sensitive_check = checked_data.get("sensitive_check", {})

        # 构建拦截记录
        filtered_record = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": data_type,
            "url": flow.request.url if hasattr(flow, 'request') else "N/A",
            "host": checked_data.get("host", "N/A"),
            "match_count": sensitive_check.get("total_matches", 0),
            "is_sensitive": sensitive_check.get("is_sensitive", False),
            "sensitive_matches": checked_data.get("sensitive_matches", []),
            "action_taken": sensitive_check.get("action_taken", "none"),
            "threshold": get_sensitivity_threshold()
        }

        # 如果是响应，添加状态码信息
        if data_type == "response" and hasattr(flow, 'response'):
            filtered_record["status_code"] = flow.response.status_code

        # 写入被拦截内容文件
        self._write_to_file(filtered_record, self.filtered_file)

        # 记录日志
        ctx.log.warn(f"📋 记录被拦截内容: {flow.request.url} - 匹配次数: {filtered_record['match_count']}")

    def _parse_request(self, flow):
        """解析HTTP请求"""
        request = flow.request

        request_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "request",
            "method": request.method,
            "url": request.url,
            "host": request.host,
            "path": urlparse(request.url).path,
            "is_youtube": "youtube.com" in request.host or "youtu.be" in request.host
        }

        video_info = self.extractor.extract_video_info(request.url, dict(request.headers))
        if video_info:
            request_info["video_info"] = video_info

        if request.text:
            extracted_content = self.extractor.extract_content(request.text)
            if extracted_content:
                request_info["extracted_content"] = extracted_content

        return request_info

    def _parse_response(self, flow):
        """解析HTTP响应"""
        response = flow.response

        response_info = {
            "timestamp": datetime.datetime.now().isoformat(),
            "type": "response",
            "status_code": response.status_code,
            "url": flow.request.url,
            "host": flow.request.host,
            "is_youtube": "youtube.com" in flow.request.host or "youtu.be" in flow.request.host
        }

        if response.text:
            extracted_content = self.extractor.extract_content(response.text)
            if extracted_content:
                response_info["extracted_content"] = extracted_content

        return response_info

    def request(self, flow: mitmproxy.http.HTTPFlow):
        flow.request.headers.pop("If-Modified-Since", None)
        flow.request.headers.pop("If-None-Match", None)

        self.num_requests += 1
        self.stats["total_requests"] += 1

        is_youtube = "youtube.com" in flow.request.host or "youtu.be" in flow.request.host
        if is_youtube:
            self.stats["youtube_requests"] += 1
            ctx.log.info(f"🎥 YouTube请求 #{self.num_requests}: {flow.request.url}")

        request_info = self._parse_request(flow)

        # 进行敏感词审查
        checked_request = check_and_filter_data(request_info)
        self._write_to_file(checked_request)

        # 记录敏感请求到被拦截文件
        if checked_request.get("sensitive_check", {}).get("is_sensitive", False):
            self._log_filtered_content(flow, checked_request, "request")
            ctx.log.warn(f"🚨 敏感请求拦截: {flow.request.url}")

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # 首先检查是否是YouTube流量
        is_youtube = "youtube.com" in flow.request.host or "youtu.be" in flow.request.host
        if not is_youtube:
            return

        # ==================== 核心修改点 ====================
        # 主动为所有YouTube API响应添加禁止缓存的头信息
        # 这是解决刷新问题的关键：确保浏览器从不缓存API数据
        # 这样每次刷新都会经过我们的代理进行过滤检查
        if "youtubei/v1/" in flow.request.path:
            flow.response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            flow.response.headers["Pragma"] = "no-cache"
            flow.response.headers["Expires"] = "0"
            ctx.log.info(f"📋 已为API响应 {flow.request.url} 强制设置无缓存头")
        # ====================================================

        ctx.log.info(f"🔍 分析YouTube响应: {flow.request.url}")

        response_info = self._parse_response(flow)

        # 打印提取的内容用于调试
        if response_info.get("extracted_content"):
            ctx.log.info(f"📋 提取的内容字段: {list(response_info['extracted_content'].keys())}")
            for field, values in response_info["extracted_content"].items():
                for i, value in enumerate(values[:3]):  # 只显示前3个值
                    ctx.log.info(f"   {field}[{i}]: {value[:100]}...")  # 截断长文本

        # 进行敏感词审查
        checked_response = check_and_filter_data(response_info)

        # 打印审查结果
        match_count = checked_response.get("sensitive_check", {}).get("total_matches", 0)
        threshold = get_sensitivity_threshold()
        ctx.log.info(f"🎯 敏感词匹配次数: {match_count} (阈值: {threshold})")

        if match_count > 0:
            ctx.log.info(f"🔍 匹配详情: {checked_response.get('sensitive_matches', [])}")

        self._write_to_file(checked_response)

        # 记录所有响应到被拦截文件（无论是否敏感）
        if checked_response.get("sensitive_check", {}).get("total_matches", 0) > 0:
            self._log_filtered_content(flow, checked_response, "response")

        # 如果响应内容敏感，进行拦截处理
        if checked_response.get("sensitive_check", {}).get("is_sensitive", False):
            self.stats["sensitive_blocks"] += 1

            ctx.log.warn(f"🚨 拦截敏感响应: {flow.request.url}")
            ctx.log.warn(f"   匹配次数: {checked_response['sensitive_check']['total_matches']}")
            ctx.log.warn(f"   当前阈值: {threshold}")

            # 尝试将响应文本作为JSON进行细粒度过滤
            if flow.response.text:
                try:
                    # 1. 将原始响应文本解析为Python字典
                    original_data = json.loads(flow.response.text)

                    # 2. 使用 sensitive_filter.py 中的函数替换敏感内容
                    #    这个函数会递归遍历数据，将包含敏感词的字符串替换掉
                    modified_data = sensitive_filter.replace_sensitive_content(original_data)

                    # 3. 将修改后的字典转换回JSON字符串，并设置为新的响应体
                    flow.response.text = json.dumps(modified_data, ensure_ascii=False)
                    flow.response.headers["X-Content-Filtered"] = "true"  # 添加一个头，表示内容已被过滤

                    ctx.log.info(f"✅ 成功过滤响应中的敏感内容，页面可正常加载。")

                except json.JSONDecodeError:
                    # 如果响应不是有效的JSON，无法进行细粒度过滤，执行回退策略
                    ctx.log.warn(f"⚠️ 响应不是有效的JSON，无法进行内容替换。返回通用过滤消息。")
                    flow.response.text = "Content filtered due to sensitive material (non-JSON response)"
                    flow.response.status_code = 403
                except Exception as e:
                    ctx.log.error(f"响应过滤时发生未知错误: {e}")
                    flow.response.text = "Error during content filtering"
                    flow.response.status_code = 500

        # 记录统计信息
        if checked_response["is_youtube"]:
            content_count = len(checked_response.get("extracted_content", {}))
            ctx.log.info(f"📺 YouTube响应: 状态码 {flow.response.status_code}, 内容字段 {content_count}")

    def done(self):
        """mitmproxy结束时调用"""
        stats = get_filter_stats()
        self.stats.update(stats)

        # 更新主输出文件
        with open(self.output_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 50 + "\n")
            f.write("审查统计信息:\n")
            json.dump(self.stats, f, ensure_ascii=False, indent=2)
            f.write("\n" + "=" * 50 + "\n")

        # 更新被拦截内容文件
        with open(self.filtered_file, 'a', encoding='utf-8') as f:
            f.write("\n" + "=" * 50 + "\n")
            f.write("拦截统计:\n")
            f.write(f"总拦截次数: {self.stats['sensitive_blocks']}\n")
            f.write(f"总请求数: {self.stats['total_requests']}\n")
            f.write(f"YouTube请求数: {self.stats['youtube_requests']}\n")
            f.write(f"最终敏感度阈值: {get_sensitivity_threshold()}\n")
            f.write("=" * 50 + "\n")


# 添加捕获器到mitmproxy
addons = [YouTubeContentCapture()]


# 添加命令行参数处理
def configure(updated):
    """配置更新时的回调函数"""
    ctx.log.info("配置已更新")