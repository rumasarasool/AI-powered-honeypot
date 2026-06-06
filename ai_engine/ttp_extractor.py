import ast
import json
import os
import re
import time

import pandas as pd
from dotenv import load_dotenv
from groq import Groq


# Step 1: Define the exact system prompt required by the specification.
SYSTEM_PROMPT = (
	"You are an expert cybersecurity analyst implementing MITRE ATT&CK framework. "
	"Analyze attack patterns and commands. Always respond with valid JSON only, no extra text."
)

# Step 2: Add the chain-of-thought hint as an additional system instruction.
CHAIN_OF_THOUGHT_HINT = "Think step by step before responding to the system prompt"

# Step 3: Define the exact user prompt template required by the specification.
USER_PROMPT_TEMPLATE = (
	"Analyze this attack: {attack_data}. Return JSON with exactly these fields: "
	"ttp_name, mitre_category, mitre_id, severity (Low/Medium/High/Critical), explanation"
)

# Step 4: Define the output file path for JSONL results.
OUTPUT_PATH = "data/ttps.json"

# Step 5: List the required JSON fields to enforce response shape.
REQUIRED_FIELDS = [
	"ttp_name",
	"mitre_category",
	"mitre_id",
	"severity",
	"explanation",
]


def load_api_key():
	"""Load the Groq API key from the .env file."""
	# Step 1: Load environment variables from the .env file.
	load_dotenv()

	# Step 2: Read the Groq API key from environment variables.
	api_key = os.getenv("GROQ_API_KEY")

	# Step 3: Fail fast if the key is missing.
	if not api_key:
		raise RuntimeError("GROQ_API_KEY was not found in the environment or .env file.")

	# Step 4: Return the validated API key.
	return api_key


def load_csv(path):
	"""Load a CSV file or return an empty DataFrame if missing."""
	# Step 1: Return an empty DataFrame if the file is missing.
	if not os.path.exists(path):
		return pd.DataFrame()

	# Step 2: Load the CSV file into a DataFrame.
	return pd.read_csv(path)


def extract_attack_types(ssh_df):
	"""Extract unique attack types from the SSH attacks dataset."""
	# Step 1: Prefer the Label column, but fall back to Attack Type if needed.
	if "Label" in ssh_df.columns:
		series = ssh_df["Label"]
	elif "Attack Type" in ssh_df.columns:
		series = ssh_df["Attack Type"]
	else:
		return []

	# Step 2: Return unique, non-empty attack type strings.
	return [str(value) for value in series.dropna().unique().tolist() if str(value).strip()]


def extract_commands(logs_df):
	"""Extract every command from the attack logs dataset."""
	# Step 1: Choose the commands column if present, or fall back to command.
	if "commands" in logs_df.columns:
		series = logs_df["commands"]
	elif "command" in logs_df.columns:
		series = logs_df["command"]
	else:
		return []

	# Step 2: Build a list of command strings from each row.
	commands = []

	# Step 3: Normalize each entry into a list of commands.
	for entry in series.dropna().tolist():
		if isinstance(entry, list):
			commands.extend([str(value) for value in entry])
			continue

		if isinstance(entry, str):
			cleaned = entry.strip()
			if not cleaned:
				continue
			try:
				parsed = ast.literal_eval(cleaned)
			except (ValueError, SyntaxError):
				commands.append(cleaned)
				continue

			if isinstance(parsed, list):
				commands.extend([str(value) for value in parsed])
			else:
				commands.append(str(parsed))
			continue

		commands.append(str(entry))

	# Step 4: Return the flattened command list.
	return commands


def extract_ttp(client, attack_data):
	"""Send a Groq request and return the parsed JSON response."""
	# Step 1: Build the prompt messages with the required system and user prompts.
	messages = [
		{"role": "system", "content": CHAIN_OF_THOUGHT_HINT},
		{"role": "system", "content": SYSTEM_PROMPT},
		{
			"role": "user",
			"content": USER_PROMPT_TEMPLATE.format(attack_data=attack_data),
		},
	]

	# Step 2: Call the Groq API using the llama-3.3-70b-versatile model.
	def _send_request():
		response = client.chat.completions.create(
			model="llama-3.3-70b-versatile",
			messages=messages,
		)
		raw_content = response.choices[0].message.content
		print(f"Raw API response: {raw_content}")
		return "" if raw_content is None else str(raw_content)

	# Step 3: Send the request and retry once if the response is empty.
	response_text = _send_request().strip()
	if not response_text:
		time.sleep(2)
		response_text = _send_request().strip()
		if not response_text:
			raise ValueError("Empty response after retry.")

	# Step 4: Extract JSON from any markdown code blocks if present.
	code_block_match = re.search(r"```(?:[a-zA-Z0-9_-]+)?\s*([\s\S]+?)\s*```", response_text)
	if code_block_match:
		response_text = code_block_match.group(1).strip()

	# Step 5: Parse the JSON content from the model response.
	try:
		parsed = json.loads(response_text)
	except json.JSONDecodeError as exc:
		raise ValueError(
			f"Failed to parse JSON. Response text was: {response_text}"
		) from exc

	# Step 6: Enforce the exact required fields in the output.
	output = {field: parsed.get(field) for field in REQUIRED_FIELDS}

	# Step 7: Ensure all required fields are present before returning.
	if any(output[field] is None for field in REQUIRED_FIELDS):
		raise ValueError(
			f"Response JSON is missing required fields. Response text was: {response_text}"
		)

	# Step 8: Return the normalized JSON response.
	return output


def main():
	"""Run the end-to-end TTP extraction pipeline."""
	# Step 1: Load the Groq API key from the .env file.
	api_key = load_api_key()

	# Step 2: Initialize the Groq client with the API key.
	client = Groq(api_key=api_key)

	# Step 3: Load SSH attack labels and attack log commands.
	ssh_df = load_csv("data/ssh_attacks.csv")
	logs_df = load_csv("data/attack_logs.csv")

	# Step 4: Extract unique attack types from the SSH dataset.
	attack_types = extract_attack_types(ssh_df)

	# Step 5: Extract every command from the attack logs dataset.
	commands = extract_commands(logs_df)

	# Step 6: Build the ordered list of attack inputs for analysis.
	attack_inputs = [f"attack type: {value}" for value in attack_types]
	attack_inputs.extend([f"command: {value}" for value in commands])

	# Step 7: Ensure the output directory exists before writing results.
	output_dir = os.path.dirname(OUTPUT_PATH)
	if output_dir:
		os.makedirs(output_dir, exist_ok=True)

	# Step 8: Open the JSONL output file for writing.
	with open(OUTPUT_PATH, "w", encoding="utf-8") as file_handle:
		total = len(attack_inputs)

		# Step 9: Process each input and write one JSON object per line.
		for index, attack_data in enumerate(attack_inputs, start=1):
			print(f"Processing {index}/{total}...")
			try:
				result = extract_ttp(client, attack_data)
			except Exception as exc:
				print(f"Skipping item {index} due to error: {exc}")
				time.sleep(1)
				continue

			file_handle.write(json.dumps(result))
			file_handle.write("\n")

			# Step 10: Pause between API calls to avoid rate limits.
			time.sleep(1)


if __name__ == "__main__":
	main()
