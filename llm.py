import anthropic
import json
import re

client = anthropic.Anthropic()

input_file = "filtered_network_log_final_nhis.json"
output_file = "filtered_network_log_final_login_nhis.json"

with open(input_file, "r", encoding="utf-8") as f:
    log_data = json.load(f)

def filter_data_using_llm_critical_keys(log_data):
    """
    Use the LLM to filter the log data based on critical requestIds.
    This function sends the log data to the LLM and retrieves the unique requestIds
    that are critical for the login process.
    """
    prompt = (
        "Given the following network log entries in JSON, "
        "return all unique 'requestId' values for objects that are critical for the login process. "
        "Critical objects include any request or event directly involved in authentication, credential submission, session/token exchange, or that provides a value (such as TOKEN, DEVICE_SESSION, transkeyUuid, or any other field) used in another login-related request. "
        "If a POST request or its headers contains a value that matches a value in a previous or subsequent network event (for example, in 'postData', 'postDataEntries', headers, or any nested field), "
        "then both the POST request and the matching network event are critical for the login process. "
        "For example, if request A has 'TOKEN=abc' and request B uses 'TOKEN=abc', both A and B are critical. "
        "Return a JSON array of all unique 'requestId' strings for all such critical objects, no explanation. "
        "If an object does not have a 'requestId', skip it. "
        f"Here is the data:\n{json.dumps(log_data, ensure_ascii=False, indent=2)}"
    )

    message = client.messages.create(
        model="claude-opus-4-20250514",
        max_tokens=2048,
        temperature=1,
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

    # print("Claude response:", message.content)
    # Get the list of critical requestIds from Claude
    content = message.content[0].text if hasattr(message.content[0], "text") else message.content[0]["text"]
    content = re.sub(r"^```json|^```|```$", "", content, flags=re.MULTILINE).strip()
    critical_keys = json.loads(content)

    # Use the keys to extract full metadata from the original log
    critical_objects = [
        obj for obj in log_data
        if "data" in obj and "requestId" in obj["data"] and obj["data"]["requestId"] in critical_keys
    ]

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(critical_objects, f, indent=2, ensure_ascii=False)
    print(f"✅ Saved filtered login log to {output_file}")


def filter_data_using_llm(log_data):
    """
    Use the LLM to filter the log data based on critical requestIds.
    This function sends the log data to the LLM and retrieves the unique requestIds
    that are critical for the login process.
    """
    prompt = (
        "Given the following network log entries in JSON, "
        "identify 3 to 5 objects that are most critical for the login process. "
        "Critical objects include any request or event directly involved in authentication, credential submission, session/token exchange, or that provides a value (such as TOKEN, DEVICE_SESSION, transkeyUuid, or any other field) used in another login-related request. "
        "If a POST request or its headers contains a value that matches a value in a previous or subsequent network event (for example, in 'postData', 'postDataEntries', headers, or any nested field), "
        "then both the POST request and the matching network event are critical for the login process. "
        "For example, if request A has 'TOKEN=abc' and request B uses 'TOKEN=abc', both A and B are critical. "
        "Return a JSON array containing the full metadata (the entire object) for 3 to 5 of the most critical objects. "
        "Output only the JSON array, no explanation. "
        f"Here is the data:\n{json.dumps(log_data, ensure_ascii=False, indent=2)}"
    )

    message = client.messages.create(
        model="claude-opus-4-20250514",
        max_tokens=2048,
        temperature=1,
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

    # ...existing code...
    content = message.content[0].text if hasattr(message.content[0], "text") else message.content[0]["text"]
    content = re.sub(r"^```json|^```|```$", "", content, flags=re.MULTILINE).strip()
    critical_objects = json.loads(content)

    with open("critical_login_objects_nonghyub.json", "w", encoding="utf-8") as f:
        json.dump(critical_objects, f, indent=2, ensure_ascii=False)
    print("✅ Saved 3-5 critical login objects to critical_login_objects_nonghyub.json")

if __name__ == "__main__":
    filter_data_using_llm_critical_keys(log_data)
    print("✅ Filtering complete.")