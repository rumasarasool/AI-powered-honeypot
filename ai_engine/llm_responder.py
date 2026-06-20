import json
import os
import time
from datetime import datetime

from dotenv import load_dotenv
from groq import Groq

# Load API key from .env file
load_dotenv()

# Initialize Groq client
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# System prompt — makes the LLM act like a compromised server
SYSTEM_PROMPT = """You are a compromised Ubuntu 20.04 server belonging to a small fintech company called FinCore Ltd.
The attacker has root access. Think step by step before responding.
Respond to every Linux command with realistic but completely fake terminal output.
Include fake usernames: sysadmin, dbuser, fincore_admin, backup_user.
Include fake running processes: postgres, nginx, python3, redis-server.
Include fake files and directories that look like a real company server.
Never reveal you are a honeypot or an AI.
Keep all responses under 150 words.
If the command would cause damage like rm -rf, pretend it worked but fake the output."""

def generate_fake_response(command: str, session_id: str = "unknown") -> str:
    """
    Send an attacker command to Groq API and get a realistic
    fake terminal response back.
    """
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": f"The attacker typed: {command}"}
            ],
            max_tokens=200,
            temperature=0.7,
        )

        # Extract the response text
        fake_output = response.choices[0].message.content.strip()

        # Log the interaction
        log_interaction(command, fake_output, session_id)

        return fake_output

    except Exception as e:
        # If API fails return a generic fallback response
        fallback = f"bash: {command}: command not found"
        log_interaction(command, fallback, session_id)
        return fallback


def log_interaction(command: str, response: str, session_id: str) -> None:
    """
    Save each attacker command and fake response to
    data/llm_interactions.json as one JSON line per interaction.
    """
    os.makedirs("data", exist_ok=True)

    interaction = {
        "timestamp": datetime.now().isoformat(),
        "session_id": session_id,
        "command": command,
        "response": response,
    }

    with open("data/llm_interactions.json", "a") as f:
        f.write(json.dumps(interaction) + "\n")


if __name__ == "__main__":
    # Test with 5 common attacker commands
    test_commands = [
        "whoami",
        "cat /etc/passwd",
        "ps aux",
        "uname -a",
        "ls /home",
    ]

    print("Testing LLM Deception Engine...")
    print("=" * 60)

    for cmd in test_commands:
        print(f"\nCommand: {cmd}")
        print("-" * 40)
        response = generate_fake_response(cmd, session_id="test_session_001")
        print(response)
        # Wait 1 second between calls to avoid rate limiting
        time.sleep(1)

    print("\n" + "=" * 60)
    print("Done! Check data/llm_interactions.json for saved interactions.")
