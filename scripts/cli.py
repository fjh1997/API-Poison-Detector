#!/usr/bin/env python3
"""
API中转站投毒检测工具 - 命令行界面

使用方式：
    python cli.py monitor --relay-url https://api.example.com
    python cli.py demo --attack system_prompt_injection
    python cli.py analyze --file request.json
"""

import argparse
import asyncio
import json
import sys
import os
from pathlib import Path

# 添加detector目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'detector'))

from detector import PoisonDetector, ThreatLevel, DetectorProxy
from poison_demo import PoisonDemo, print_comparison


def cmd_monitor(args):
    """启动监控代理"""
    print(f"启动监控代理...")
    print(f"中转站地址: {args.relay_url}")
    print(f"监听地址: http://{args.host}:{args.port}")
    print("请使用 detector/detector.py 配置文件方式启动代理")
    print("或直接运行: python detector/detector.py")


def cmd_demo(args):
    """运行攻击演示"""
    demo = PoisonDemo()

    if args.attack == 'all':
        # 演示所有攻击
        print("""
╔══════════════════════════════════════════════════════════════╗
║           API中转站投毒攻击演示 - 安全研究用途              ║
╚══════════════════════════════════════════════════════════════╝
        """)

        sample_request = demo._get_sample_request()
        sample_response = demo._get_sample_response()

        for attack_name in demo.attacks:
            result = demo.demonstrate_attack(attack_name, sample_request, sample_response)
            print_comparison(
                attack_name,
                result['original'],
                result['poisoned']
            )
    else:
        # 演示指定攻击
        if args.attack not in demo.attacks:
            print(f"未知攻击类型: {args.attack}")
            print(f"可用的攻击类型: {', '.join(demo.attacks.keys())}")
            return

        result = demo.demonstrate_attack(args.attack)
        print_comparison(
            args.attack,
            result['original'],
            result['poisoned']
        )


def cmd_analyze(args):
    """分析请求/响应文件"""
    detector = PoisonDetector()

    with open(args.file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    if 'messages' in data:
        detections = detector.analyze_request(data, {})
    elif 'choices' in data:
        detections = detector.analyze_response(data)
    else:
        print("无法识别文件格式")
        return

    for d in detections:
        detector.alerts.append(d)

    detector.print_report()


def cmd_check(args):
    """快速检查API中转站安全性"""
    import requests

    print(f"检查中转站安全性: {args.relay_url}")

    # 构建测试请求
    test_request = {
        "model": args.model or "gpt-3.5-turbo",
        "messages": [
            {"role": "user", "content": "Hello, this is a security test."}
        ],
        "max_tokens": 100
    }

    headers = {
        "Content-Type": "application/json"
    }
    if args.api_key:
        headers["Authorization"] = f"Bearer {args.api_key}"

    # 发送请求
    try:
        import time
        start_time = time.time()
        response = requests.post(
            f"{args.relay_url}/v1/chat/completions",
            json=test_request,
            headers=headers,
            timeout=30
        )
        latency_ms = (time.time() - start_time) * 1000

        response_data = response.json()

        # 分析响应
        detector = PoisonDetector()
        detections = detector.analyze_response(response_data)

        # 打印结果
        print(f"\n响应状态码: {response.status_code}")
        print(f"响应延迟: {latency_ms:.0f}ms")

        if detections:
            print(f"\n⚠️  检测到 {len(detections)} 个可疑项:")
            for d in detections:
                print(f"  - [{d.threat_level.value}] {d.description}")
        else:
            print("\n✅ 未检测到明显威胁")

        # 显示响应摘要
        if 'choices' in response_data:
            content = response_data['choices'][0].get('message', {}).get('content', '')
            print(f"\n响应内容摘要:")
            print(content[:200] + "..." if len(content) > 200 else content)

    except Exception as e:
        print(f"\n❌ 检查失败: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='API中转站投毒检测工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 启动监控代理
  python cli.py monitor --relay-url https://api.example.com --api-key sk-xxx

  # 运行攻击演示
  python cli.py demo --attack all
  python cli.py demo --attack system_prompt_injection

  # 分析请求文件
  python cli.py analyze --file request.json

  # 快速检查中转站安全性
  python cli.py check --relay-url https://api.example.com
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # monitor 子命令
    monitor_parser = subparsers.add_parser('monitor', help='启动监控代理')
    monitor_parser.add_argument('--host', default='127.0.0.1', help='监听地址')
    monitor_parser.add_argument('--port', type=int, default=8080, help='监听端口')
    monitor_parser.add_argument('--relay-url', required=True, help='中转站API地址')
    monitor_parser.add_argument('--api-key', help='API密钥')
    monitor_parser.add_argument('--block-critical', action='store_true', help='阻断严重威胁')
    monitor_parser.add_argument('--no-detection', action='store_true', help='禁用检测')
    monitor_parser.add_argument('--alert-webhook', help='告警Webhook地址')
    monitor_parser.set_defaults(func=cmd_monitor)

    # demo 子命令
    demo_parser = subparsers.add_parser('demo', help='运行攻击演示')
    demo_parser.add_argument(
        '--attack',
        default='all',
        choices=['all', 'system_prompt_injection', 'tool_call_injection',
                 'response_poisoning', 'function_call_tampering',
                 'data_exfiltration', 'hidden_instruction'],
        help='要演示的攻击类型'
    )
    demo_parser.set_defaults(func=cmd_demo)

    # analyze 子命令
    analyze_parser = subparsers.add_parser('analyze', help='分析请求/响应文件')
    analyze_parser.add_argument('--file', required=True, help='JSON文件路径')
    analyze_parser.set_defaults(func=cmd_analyze)

    # check 子命令
    check_parser = subparsers.add_parser('check', help='快速检查中转站安全性')
    check_parser.add_argument('--relay-url', required=True, help='中转站API地址')
    check_parser.add_argument('--api-key', help='API密钥')
    check_parser.add_argument('--model', help='模型名称')
    check_parser.set_defaults(func=cmd_check)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == '__main__':
    main()
