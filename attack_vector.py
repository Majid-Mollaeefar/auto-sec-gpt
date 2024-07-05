# attack_vector.py

import google.generativeai as genai
import json
import os
from openai import OpenAI
import re

def create_attack_scenario_vector_prompt(api_key, model_name, input_file_name, output_file_name):
    client = OpenAI(api_key=api_key)

    # Read the JSON file
    with open(input_file_name, 'r') as file:
        data = json.load(file)

    results = []

    for item in data:
        asset = item["Asset"]
        threats = item["Threats"]
        
        threat_list = threats.split(',')

        for threat in threat_list:
            threat = threat.strip()
            prompt = (
            f"Asset: {asset}\n"
            f"Threats: {threats}\n"
            f""" 
            As a seasoned cybersecurity expert with over 20 years of experience in the automotive sector, you bring a wealth of knowledge and proficiency in safeguarding automotive systems. Your task is to conduct an attack model for the application scenario where for each identified threat related to an asset, identify attacker objectives, identify attack scenarios, and attack vectors. 
            When providing the attack model, use a JSON formatted response with the key "attack_model". Under "attack_model", include an array of objects with the keys "Threat", "Attacker Objectives", "Attack Scenario", and "Attack Vector".
            Example of expected JSON response format:
                
                    {{
                    "attack_model": [	
                        {{
                        "Threat": "Threat name",
                        "Attacker Objectives: " 1. objective 1, 2. objective 2, ..."
                        "Attack Scenario": "Attack scenario description",
                        "Attack Vector": "Attack vector (or attack path) description"
                        }}
                        // ... more threats
                    ]
                    }}
                    
            """)
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=4000,
            )
            response_content = response.choices[0].message.content

            # Extract the relevant information from the response
            attacker_objectives = clean_text(extract_section(response_content, "Attacker Objectives"))
            attack_scenario = clean_text(extract_section(response_content, "Attack Scenario"))
            attack_vector = clean_text(extract_section(response_content, "Attack Vector"))

            results.append({
                "Threat": threat,
                "Attacker Objectives": attacker_objectives,
                "Attack Scenario": attack_scenario,
                "Attack Vector": attack_vector
            })

    output = {
        "attack_model": results
    }

    # Write the results to the output file
    with open(output_file_name, 'w') as outfile:
        json.dump(output, outfile, indent=4)

def extract_section(text, section_title):
    """
    Extracts a section from the response text based on the section title.

    Parameters:
    text (str): The response text from which to extract the section.
    section_title (str): The title of the section to extract.

    Returns:
    str: The extracted section content.
    """
    section_start = text.find(section_title)
    if section_start == -1:
        return ""
    
    section_start += len(section_title) + 1
    section_end = text.find("\n", section_start)
    if section_end == -1:
        section_end = len(text)
    
    return text[section_start:section_end].strip()

def clean_text(text):
    """
    Cleans the extracted text to remove unwanted characters.

    Parameters:
    text (str): The text to be cleaned.

    Returns:
    str: The cleaned text.
    """
    # Remove unwanted characters
    text = re.sub(r'[\:\[\]\"\,]', '', text)
    text = re.sub(r'\\u2019', "'", text)  # Replace unicode apostrophe with normal apostrophe
    text = text.replace('\\', '')  # Remove backslashes

    # Ensure the text is not empty
    return text if text else "Information not provided."


# Function to convert JSON to Markdown for display.    
def json_to_markdown_attack_model(output_file_name):
    with open(output_file_name, 'r') as file:
        attack_model_data = json.load(file)

    if "attack_model" not in attack_model_data:
        return "No attack model found in the JSON file."

    attack_model = attack_model_data["attack_model"]
    
    markdown_output_attack_model = "## Attack Model\n\n"
    
    # Start the markdown table with headers
    markdown_output_attack_model += "| Threat | Attacker Objectives | Attack Scenario | Attack Vector |\n"
    markdown_output_attack_model += "|--------|---------------------|-----------------|---------------|\n"
    
    # Fill the table rows with the attack model data
    for attack in attack_model:
        markdown_output_attack_model += f"| {attack['Threat']} | {attack['Attacker Objectives']} | {attack['Attack Scenario']} | {attack['Attack Vector']} |\n"
    
    return markdown_output_attack_model



# Example usage
# base_path = os.getcwd()  
# input_file_name = os.path.join(base_path, ".files\\threats.json")
# api_key = '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'
# output_file_name = os.path.join(base_path, ".files\\attack-model.json")
# model_name= "gpt-4o"
# create_attack_scenario_vector_prompt(api_key, model_name, input_file_name, output_file_name)