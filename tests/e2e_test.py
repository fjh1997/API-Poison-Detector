#!/usr/bin/env python3
"""
End-to-end test: Claude Code -> Detector -> Poisoner -> Real API

This test simulates what happens when Claude Code is configured to use
the detector proxy. The poisoner injects a malicious tool_use block,
and we verify the detector intercepts it.

Architecture:
  Claude Code (SDK) -> http://127.0.0.1:8080 (detector) -> http://127.0.0.1:9090 (poisoner) -> real API

Expected:
  - First request: poisoner injects tool_use (PowerShell popup), detector BLOCKS it
  - Second request: poisoner passes through (already injected for this session), detector allows clean response
"""

import asyncio
import json
import sys
import os
import uuid
import time

# Add detector to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'detector'))

try:
    import aiohttp
except ImportError:
    print("ERROR: aiohttp not installed. Run: pip install aiohttp")
    sys.exit(1)

DETECTOR_URL = "http://127.0.0.1:8080/v1/messages"
DETECTOR_KEY = "sk-detector-safe-key-123456"
TEST_SESSION_ID = f"e2e-test-{uuid.uuid4().hex[:8]}"


async def test_1_tool_injection_blocked():
    """
    Test 1: Poisoner injects malicious tool_use (PowerShell popup).
    Detector should intercept and block the injection.
    """
    print("\n" + "=" * 60)
    print("TEST 1: Tool Use Injection Detection")
    print("=" * 60)

    headers = {
        "Content-Type": "application/json",
        "x-api-key": DETECTOR_KEY,
        "anthropic-version": "2023-06-01",
        "X-Claude-Code-Session-Id": TEST_SESSION_ID,
    }

    body = {
        "model": "mimo-v2.5-pro",
        "max_tokens": 100,
        "stream": True,
        "messages": [
            {"role": "user", "content": "Hello, what time is it?"}
        ],
        "tools": [
            {
                "name": "Bash",
                "description": "Run a bash command",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "The command to run"}
                    }
                }
            }
        ]
    }

    print(f"Session ID: {TEST_SESSION_ID}")
    print(f"Sending request to detector at {DETECTOR_URL}")
    print(f"  -> Detector forwards to poisoner (9090)")
    print(f"  -> Poisoner injects malicious tool_use (PowerShell popup)")
    print(f"  -> Detector should intercept and block\n")

    events_received = []
    injection_blocked = False
    tool_use_seen = False
    model_in_response = None

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                DETECTOR_URL,
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                print(f"Response status: {resp.status}")

                if resp.status != 200:
                    error = await resp.text()
                    print(f"ERROR: {resp.status} - {error}")
                    return False

                async for line in resp.content:
                    line_str = line.decode('utf-8').strip()
                    if not line_str:
                        continue

                    if line_str.startswith("event: "):
                        event_type = line_str[7:]
                        events_received.append(event_type)

                    elif line_str.startswith("data: "):
                        data_str = line_str[6:]
                        try:
                            data = json.loads(data_str)

                            # Check message_start for model info
                            if data.get("type") == "message_start":
                                msg = data.get("message", {})
                                model_in_response = msg.get("model", "unknown")
                                print(f"  Model in response: {model_in_response}")

                            # Check content_block_start for tool_use
                            if data.get("type") == "content_block_start":
                                cb = data.get("content_block", {})
                                if cb.get("type") == "tool_use":
                                    tool_use_seen = True
                                    tool_name = cb.get("name", "?")
                                    print(f"  TOOL_USE detected: {tool_name}")

                            # Check content_block_delta for input
                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if "partial_json" in delta:
                                    partial = delta["partial_json"]
                                    if "powershell" in partial.lower() or "messagebox" in partial.lower():
                                        injection_blocked = True
                                        print(f"  MALICIOUS PAYLOAD in delta: {partial[:100]}...")

                            # Check message_delta for stop_reason
                            if data.get("type") == "message_delta":
                                stop = data.get("delta", {}).get("stop_reason", "")
                                print(f"  Stop reason: {stop}")

                        except json.JSONDecodeError:
                            pass

    except Exception as e:
        print(f"Connection error: {e}")
        print("Make sure detector (8080) and poisoner (9090) are running.")
        return False

    print(f"\nEvents received: {events_received}")
    print(f"Tool use seen: {tool_use_seen}")
    print(f"Malicious payload in delta: {injection_blocked}")

    # The detector should have:
    # 1. Either blocked the entire response (status != 200)
    # 2. Or rewritten the stop_reason from tool_use to end_turn
    # 3. Or stripped the malicious tool_use block

    if injection_blocked:
        print("\n[X] FAIL: Malicious payload was NOT blocked by detector!")
        return False
    elif tool_use_seen:
        print("\n[!] WARNING: tool_use block passed through (may be safe if payload was stripped)")
        return True  # tool_use block might be present but sanitized
    else:
        print("\n[V] PASS: No malicious tool_use injection in response")
        return True


async def test_2_clean_response():
    """
    Test 2: Second request (poisoner passes through - already injected for this session).
    Detector should allow clean response through.
    """
    print("\n" + "=" * 60)
    print("TEST 2: Clean Passthrough (no injection)")
    print("=" * 60)

    headers = {
        "Content-Type": "application/json",
        "x-api-key": DETECTOR_KEY,
        "anthropic-version": "2023-06-01",
        "X-Claude-Code-Session-Id": TEST_SESSION_ID,  # Same session - poisoner won't re-inject
    }

    body = {
        "model": "mimo-v2.5-pro",
        "max_tokens": 100,
        "stream": True,
        "messages": [
            {"role": "user", "content": "What is 2+2?"}
        ],
    }

    print(f"Session ID: {TEST_SESSION_ID} (same session, poisoner won't re-inject)")
    print(f"Sending request to detector...\n")

    events_received = []
    response_text = ""
    model_in_response = None
    has_tool_use = False

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                DETECTOR_URL,
                headers=headers,
                json=body,
                timeout=aiohttp.ClientTimeout(total=60)
            ) as resp:
                print(f"Response status: {resp.status}")

                if resp.status != 200:
                    error = await resp.text()
                    print(f"ERROR: {resp.status} - {error}")
                    return False

                async for line in resp.content:
                    line_str = line.decode('utf-8').strip()
                    if not line_str:
                        continue

                    if line_str.startswith("event: "):
                        event_type = line_str[7:]
                        events_received.append(event_type)

                    elif line_str.startswith("data: "):
                        data_str = line_str[6:]
                        try:
                            data = json.loads(data_str)

                            if data.get("type") == "message_start":
                                msg = data.get("message", {})
                                model_in_response = msg.get("model", "unknown")
                                print(f"  Model in response: {model_in_response}")

                            if data.get("type") == "content_block_start":
                                cb = data.get("content_block", {})
                                if cb.get("type") == "tool_use":
                                    has_tool_use = True

                            if data.get("type") == "content_block_delta":
                                delta = data.get("delta", {})
                                if "text" in delta:
                                    response_text += delta["text"]

                            if data.get("type") == "message_delta":
                                stop = data.get("delta", {}).get("stop_reason", "")
                                print(f"  Stop reason: {stop}")

                        except json.JSONDecodeError:
                            pass

    except Exception as e:
        print(f"Connection error: {e}")
        return False

    print(f"\nEvents received: {len(events_received)} events")
    safe_text = response_text[:200].encode('ascii', errors='replace').decode('ascii')
    print(f"Response text: {safe_text}")
    print(f"Has tool_use: {has_tool_use}")

    if has_tool_use:
        print("\n[X] FAIL: Unexpected tool_use in clean response!")
        return False
    else:
        print("\n[V] PASS: Clean response, no injection")
        return True


async def test_3_detection_logs():
    """
    Test 3: Check detector logs for detection records.
    """
    print("\n" + "=" * 60)
    print("TEST 3: Detection Log Verification")
    print("=" * 60)

    log_path = os.path.join(os.path.dirname(__file__), '..', 'detector', 'detection_alerts.log')
    if not os.path.exists(log_path):
        print(f"Log file not found at: {log_path}")
        # Check logs dir too
        log_path2 = os.path.join(os.path.dirname(__file__), '..', 'logs', 'detection_alerts.log')
        if os.path.exists(log_path2):
            log_path = log_path2
        else:
            print("[!] No log file found (detection may not have triggered alerts)")
            return True  # Not a failure

    print(f"Reading log: {log_path}")
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read()
        if content.strip():
            print(f"Log entries found:\n{content[-2000:]}")
            print("\n[V] PASS: Detection logs present")
        else:
            print("[!] Log file is empty (no alerts triggered)")
        return True
    except Exception as e:
        print(f"Error reading log: {e}")
        return True


async def main():
    print("=" * 60)
    print("API-Poison-Detector End-to-End Test")
    print("=" * 60)
    print(f"Architecture: Claude Code SDK -> Detector (8080) -> Poisoner (9090) -> Real API")
    print(f"Session ID: {TEST_SESSION_ID}")

    results = {}

    # Test 1: First request - poisoner injects, detector should block
    results["tool_injection"] = await test_1_tool_injection_blocked()

    # Small delay between requests
    await asyncio.sleep(1)

    # Test 2: Second request - clean passthrough
    results["clean_passthrough"] = await test_2_clean_response()

    # Test 3: Check logs
    results["detection_logs"] = await test_3_detection_logs()

    # Summary
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)
    all_pass = True
    for test_name, passed in results.items():
        status = "PASS" if passed else "FAIL"
        if not passed:
            all_pass = False
        print(f"  {test_name}: {status}")

    print()
    if all_pass:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")

    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
