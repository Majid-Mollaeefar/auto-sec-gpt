import json
import os
import streamlit as st
import pandas as pd
from openai import OpenAI  # pip install openai
from sentence_transformers import SentenceTransformer, util
import requests

# Load the NLP model for similarity comparison
model = SentenceTransformer('all-MiniLM-L6-v2')

def flatten_field(value):
    """
    Recursively converts a value (str, list, or dict) to a single string.
    """
    if isinstance(value, str):
        return value
    elif isinstance(value, list):
        return " ".join(flatten_field(item) for item in value)
    elif isinstance(value, dict):
        if "p" in value:
            return flatten_field(value["p"])
        else:
            return " ".join(flatten_field(v) for v in value.values())
    else:
        return str(value)

def load_attack_patterns(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    patterns = data.get("Attack_Pattern_Catalog", {}) \
                   .get("Attack_Patterns", {}) \
                   .get("Attack_Pattern", [])
    combined_patterns = []
    for idx, pat in enumerate(patterns):
        combined_text = ""
        for key in ['Description', 'Extended_Description']:
            if key in pat:
                combined_text += flatten_field(pat[key]) + " "
        if "Execution_Flow" in pat and "Attack_Step" in pat["Execution_Flow"]:
            steps = pat["Execution_Flow"]["Attack_Step"]
            if isinstance(steps, list):
                for step in steps:
                    combined_text += flatten_field(step.get("Description", "")) + " "
            else:
                combined_text += flatten_field(steps.get("Description", "")) + " "
        combined_patterns.append({
            "id": idx,
            "raw": pat,
            "combined_text": combined_text.strip()
        })
    return combined_patterns

def load_threat_scenarios(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    scenarios = []
    if "assets" in data:
        for asset in data["assets"]:
            asset_name = asset.get("name", "Unknown Asset")
            for threat in asset.get("threats", []):
                threat_name = threat.get("name", "Unknown Threat")
                for vector in threat.get("vectors", []):
                    vector_name = vector.get("vector_name", "Unknown Vector")
                    for scenario in vector.get("scenarios", []):
                        scenario_id = scenario.get("scenario_id", "")
                        scenario_desc = scenario.get("scenario_description", "")
                        full_text = f"Asset: {asset_name}. Threat: {threat_name}. Vector: {vector_name}. Scenario: {scenario_desc}"
                        scenarios.append({
                            "id": scenario_id,
                            "asset": asset_name,
                            "threat": threat_name,
                            "vector": vector_name,
                            "scenario_text": full_text
                        })
    else:
        scenarios = json.load(f)
    return scenarios

def compute_similarities(threat_text, attack_patterns, threshold=0.6):
    threat_embedding = model.encode(threat_text, convert_to_tensor=True)
    similar_patterns = []
    for pat in attack_patterns:
        pat_embedding = model.encode(pat["combined_text"], convert_to_tensor=True)
        cosine_sim = util.pytorch_cos_sim(threat_embedding, pat_embedding).item()
        if cosine_sim >= threshold:
            similar_patterns.append((cosine_sim, pat))
    similar_patterns.sort(key=lambda x: x[0], reverse=True)
    return similar_patterns

def generate_updated_threat_scenario(threat_desc, attack_details, scenario_details, api_key, model_name="gpt-4o-mini"):
    """
    Uses generative AI to produce an updated threat scenario description.

    Parameters:
      - threat_desc: The original threat scenario description.
      - attack_details: A string containing detailed attack pattern information.
      - scenario_details: A dictionary containing keys 'asset', 'threat', 'vector', and 'scenario_text'.
      - api_key: OpenAI API key.
      - model_name: The model to use (default: "gpt-4o-mini").

    Returns:
      A dictionary with keys "updated_threat_scenario", "attack_paths", and "mitigation_strategies",
      or an "error" key if generation or JSON parsing fails.
    """
    prompt = f"""
As a seasoned cybersecurity expert with deep expertise in threat modeling, your task is to update the following threat scenario by incorporating insights from a related attack pattern.

Original Threat Scenario:
{threat_desc}

Attack Pattern Details:
{attack_details}

Scenario Context:
- Asset: {scenario_details['asset']}
- Threat: {scenario_details['threat']}
- Attack Vector: {scenario_details['vector']}
- Original Scenario Description: {scenario_details['scenario_text']}

Please provide your updated threat scenario as a JSON object with the following structure:
{{
  "updated_threat_scenario": "Your updated scenario description here.",
  "attack_paths": "List or description of potential attack paths.",
  "mitigation_strategies": "List or description of recommended mitigation strategies."
}}

Ensure that your output is ONLY the JSON object with no additional text.
"""
    client = OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": "You are a helpful security analyst that outputs JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=4000
        )
        generated_text = response.choices[0].message.content.strip()

        # Remove markdown code fences if present
        if generated_text.startswith("```json") and generated_text.endswith("```"):
            generated_text = generated_text[len("```json"):]
            if generated_text.endswith("```"):
                generated_text = generated_text[:-len("```")]
        elif generated_text.startswith("```") and generated_text.endswith("```"):
            generated_text = generated_text[len("```"):]
            if generated_text.endswith("```"):
                generated_text = generated_text[:-len("```")]

        generated_text = generated_text.strip()

        # Check if the generated text is empty
        if not generated_text:
            return {"error": "Generation failed: Empty response from AI model."}

        # Attempt to parse the generated text as JSON
        try:
            parsed_json = json.loads(generated_text)
        except json.JSONDecodeError as jde:
            # Log the JSON parsing error
            st.error(f"JSON parsing failed: {jde}")
            return {"error": "Generation failed: Invalid JSON format."}

        # Further clean unicode issues (e.g. replace \u2019 with a straight quote)
        json_str = json.dumps(parsed_json)
        cleaned_json_str = json_str.replace("\\u2019", "'")
        final_json = json.loads(cleaned_json_str)
        return final_json
    except Exception as e:
        # Log any other exceptions that occur
        st.error(f"An error occurred: {e}")
        return {"error": f"Generation failed: {e}"}

def generate_updated_threat_scenario_llmlocal(threat_desc, attack_details, scenario_details, lmstudio_url, model_name):
    """
    Uses local LLM to produce an updated threat scenario description.
    """
    prompt = f"""
As a seasoned cybersecurity expert with deep expertise in threat modeling, your task is to update the following threat scenario by incorporating insights from a related attack pattern.

Original Threat Scenario:
{threat_desc}

Attack Pattern Details:
{attack_details}

Scenario Context:
- Asset: {scenario_details['asset']}
- Threat: {scenario_details['threat']}
- Attack Vector: {scenario_details['vector']}
- Original Scenario Description: {scenario_details['scenario_text']}

Please provide your updated threat scenario as a JSON object with the following structure:
{{
  "updated_threat_scenario": "Your updated scenario description here.",
  "attack_paths": "List or description of potential attack paths.",
  "mitigation_strategies": "List or description of recommended mitigation strategies."
}}

Ensure that your output is ONLY the JSON object with no additional text.
"""
    messages = [
        {"role": "system", "content": "You are a helpful security analyst that outputs JSON."},
        {"role": "user", "content": prompt}
    ]
    
    data = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.7,
        "max_tokens": 4000,
        "stream": False
    }
    
    try:
        response = requests.post(f"{lmstudio_url}/v1/chat/completions", json=data)
        if response.status_code == 200:
            response_json = response.json()
            generated_text = response_json.get("choices", [{}])[0].get("message", {}).get("content", "").strip()

            # Clean up the response
            if generated_text.startswith("```json"):
                generated_text = generated_text[7:-3]
            elif generated_text.startswith("```"):
                generated_text = generated_text[3:-3]

            # Parse JSON response
            try:
                parsed_json = json.loads(generated_text)
                return parsed_json
            except json.JSONDecodeError as jde:
                st.error(f"JSON parsing failed: {jde}")
                return {"error": "Generation failed: Invalid JSON format."}
        else:
            return {"error": f"Generation failed: LMStudio API error {response.status_code}"}
    except Exception as e:
        st.error(f"An error occurred: {e}")
        return {"error": f"Generation failed: {e}"}

def save_scenario_data(scenario_data, is_temp=True):
    """Helper function to save scenario data to JSON files"""
    try:
        base_path = os.getcwd()
        files_dir = os.path.join(base_path, ".files")
        os.makedirs(files_dir, exist_ok=True)  # Create .files directory if it doesn't exist
        
        filename = "temp_scenarios.json" if is_temp else "capec-based_scenarios.json"
        filepath = os.path.join(files_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(scenario_data, f, indent=2)
        return True
    except Exception as e:
        st.error(f"Error saving scenario data: {e}")
        return False

def clean_text_for_markdown(text):
    """Clean text to make it safe for markdown table cells"""
    if not text:
        return "N/A"
    # Replace newlines and pipe characters
    return str(text).replace("\n", " ").replace("|", "\\|").replace("\r", " ").strip()