#!/usr/bin/env python3
"""共享测试辅助函数"""

import time
import requests


def print_banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def print_step(step, text):
    print(f"\n[Step {step}] {text}")
    print("-" * 40)


def call_api(api_url, api_key, messages, model=None, max_tokens=200):
    """调用Anthropic API"""
    if model is None:
        model = "claude-sonnet-4-20250514"

    headers = {
        "Content-Type": "application/json",
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01"
    }

    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": messages
    }

    try:
        start_time = time.time()
        response = requests.post(
            f"{api_url}/v1/messages",
            headers=headers,
            json=payload,
            timeout=30
        )
        latency = (time.time() - start_time) * 1000

        return {
            "success": response.status_code == 200,
            "status": response.status_code,
            "latency": latency,
            "data": response.json() if response.status_code == 200 else {},
            "error": response.text if response.status_code != 200 else None
        }
    except Exception as e:
        return {
            "success": False,
            "status": 0,
            "latency": 0,
            "data": {},
            "error": str(e)
        }


def extract_content(response_data):
    """提取响应内容（支持Anthropic和OpenAI格式）"""
    content = ""

    # Anthropic格式
    if "content" in response_data:
        for block in response_data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")
            elif block.get("type") == "thinking":
                content += block.get("thinking", "")

    # OpenAI格式
    elif "choices" in response_data:
        content = response_data["choices"][0].get("message", {}).get("content", "")

    return content
