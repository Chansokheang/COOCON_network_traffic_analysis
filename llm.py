import anthropic
import json
import re
import argparse
import os
import sys
from typing import List, Dict, Any, Optional
from datetime import datetime

class NetworkLogAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        """Initialize the analyzer with optional API key"""
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError("Anthropic API key is required. Set it via ANTHROPIC_API_KEY environment variable or pass it to the constructor.")
        
        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.model = "claude-opus-4-20250514"
        self.max_tokens = 2048
        self.temperature = 1

    def load_log_data(self, input_file: str) -> List[Dict[str, Any]]:
        """Load and validate network log data from JSON file"""
        try:
            with open(input_file, "r", encoding="utf-8") as f:
                log_data = json.load(f)
            if not isinstance(log_data, list):
                raise ValueError("Log data must be a list of network events")
            return log_data
        except FileNotFoundError:
            print(f"❌ Error: Input file '{input_file}' not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"❌ Error: Invalid JSON in file '{input_file}'")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error loading log data: {str(e)}")
            sys.exit(1)

    def save_results(self, data: List[Dict[str, Any]], output_file: str) -> None:
        """Save analysis results to JSON file"""
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"✅ Saved results to '{output_file}'")
        except Exception as e:
            print(f"❌ Error saving results: {str(e)}")
            sys.exit(1)

    def analyze_critical_keys(self, log_data: List[Dict[str, Any]]) -> List[str]:
        """Analyze log data to identify up to 5 most critical request IDs"""
        prompt = (
            "Given the following network log entries in JSON, "
            "identify the 5 most critical 'requestId' values for objects that are essential for the login process. "
            "Focus on the most important authentication and security-related requests. "
            "Critical objects include:\n"
            "1. Primary authentication requests (login, signin)\n"
            "2. Session/token management requests\n"
            "3. Security verification requests (2FA, OTP)\n"
            "4. Requests that provide values used in other critical requests\n"
            "5. Requests that handle sensitive data exchange\n\n"
            "If a POST request or its headers contains a value that matches a value in another network event "
            "(in 'postData', 'postDataEntries', headers, or nested fields), "
            "prioritize both the POST request and the matching network event.\n\n"
            "Return a JSON array of exactly 5 unique 'requestId' strings for the most critical objects, "
            "ordered by importance. If there are fewer than 5 critical objects, return all of them. "
            "If an object does not have a 'requestId', skip it. "
            "Output only the JSON array, no explanation.\n\n"
            f"Here is the data:\n{json.dumps(log_data, ensure_ascii=False, indent=2)}"
        )

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0.7,  # Reduced temperature for more focused results
                system="You are a security-focused assistant that returns only JSON arrays of critical request IDs.",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ]
            )

            content = message.content[0].text if hasattr(message.content[0], "text") else message.content[0]["text"]
            content = re.sub(r"^```json|^```|```$", "", content, flags=re.MULTILINE).strip()
            critical_keys = json.loads(content)

            # Ensure we have at most 5 keys
            if len(critical_keys) > 5:
                print(f"⚠️  Warning: Found {len(critical_keys)} critical keys, limiting to top 5")
                critical_keys = critical_keys[:5]
            elif len(critical_keys) < 5:
                print(f"ℹ️  Note: Found {len(critical_keys)} critical keys (less than 5)")

            return critical_keys
        except Exception as e:
            print(f"❌ Error during LLM analysis: {str(e)}")
            sys.exit(1)

    def analyze_critical_objects(self, log_data: List[Dict[str, Any]], max_objects: int = 5) -> List[Dict[str, Any]]:
        """Analyze log data to identify most critical objects with full metadata"""
        prompt = (
            f"Given the following network log entries in JSON, "
            f"identify {max_objects} objects that are most critical for the login process. "
            "Critical objects include any request or event directly involved in authentication, credential submission, session/token exchange, or that provides a value (such as TOKEN, DEVICE_SESSION, transkeyUuid, or any other field) used in another login-related request. "
            "If a POST request or its headers contains a value that matches a value in a previous or subsequent network event (for example, in 'postData', 'postDataEntries', headers, or any nested field), "
            "then both the POST request and the matching network event are critical for the login process. "
            "For example, if request A has 'TOKEN=abc' and request B uses 'TOKEN=abc', both A and B are critical. "
            f"Return a JSON array containing the full metadata (the entire object) for the {max_objects} most critical objects. "
            "Output only the JSON array, no explanation. "
            f"Here is the data:\n{json.dumps(log_data, ensure_ascii=False, indent=2)}"
        )

        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system="You are a helpful assistant that returns only JSON arrays.",
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": prompt
                            }
                        ]
                    }
                ]
            )

            content = message.content[0].text if hasattr(message.content[0], "text") else message.content[0]["text"]
            content = re.sub(r"^```json|^```|```$", "", content, flags=re.MULTILINE).strip()
            return json.loads(content)
        except Exception as e:
            print(f"❌ Error during LLM analysis: {str(e)}")
            sys.exit(1)

    def filter_by_critical_keys(self, log_data: List[Dict[str, Any]], critical_keys: List[str]) -> List[Dict[str, Any]]:
        """Filter log data to include only objects with critical request IDs"""
        return [
            obj for obj in log_data
            if "data" in obj and "requestId" in obj["data"] and obj["data"]["requestId"] in critical_keys
        ]

def main():
    parser = argparse.ArgumentParser(description="Analyze network logs using Claude AI")
    parser.add_argument("--input", "-i", required=True, help="Input JSON file containing network logs")
    parser.add_argument("--output", "-o", help="Output JSON file for filtered results")
    parser.add_argument("--mode", "-m", choices=["keys", "objects"], default="keys",
                      help="Analysis mode: 'keys' for request IDs, 'objects' for full objects")
    parser.add_argument("--max-objects", type=int, default=5,
                      help="Maximum number of critical objects to return (only in 'objects' mode)")
    parser.add_argument("--api-key", help="Anthropic API key (optional if set in environment)")

    args = parser.parse_args()

    # Set default output filename if not provided
    if not args.output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output = f"filtered_network_log_{args.mode}_{timestamp}.json"

    try:
        analyzer = NetworkLogAnalyzer(api_key=args.api_key)
        log_data = analyzer.load_log_data(args.input)

        if args.mode == "keys":
            print("🔍 Analyzing network logs for critical request IDs...")
            critical_keys = analyzer.analyze_critical_keys(log_data)
            filtered_data = analyzer.filter_by_critical_keys(log_data, critical_keys)
            print(f"✅ Found {len(critical_keys)} critical request IDs")
        else:
            print(f"🔍 Analyzing network logs for {args.max_objects} most critical objects...")
            filtered_data = analyzer.analyze_critical_objects(log_data, args.max_objects)
            print(f"✅ Found {len(filtered_data)} critical objects")

        analyzer.save_results(filtered_data, args.output)
        print("✅ Analysis complete!")

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()