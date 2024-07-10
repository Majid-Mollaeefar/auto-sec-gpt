# threat_model.py

import json
import google.generativeai as genai
from openai import OpenAI
import streamlit as st


# Function to convert JSON to Markdown for display.    
def json_to_markdown(threat_model):
    markdown_output = "## Threat Model\n\n"
    
    # Start the markdown table with headers
    markdown_output += "| Asset | Threats | Potential Consequences |\n"
    markdown_output += "|-------|---------|------------------|\n"
    
    # Fill the table rows with the threat model data
    for threat in threat_model:
        markdown_output += f"| {threat['Asset']} | {threat['Threats']} | {threat['Potential Consequences']} |\n"
    
    
    return markdown_output

# Function to create a prompt for generating a threat model
# def create_threat_model_prompt(app_type, authentication, internet_facing, sensitive_data, app_input):

def create_threat_model_prompt(app_input, vehicle_class, autonomous_level, connectivity_features, critical_systems, external_interfaces, data_types, storage_locations):
    prompt = f"""

As a seasoned cybersecurity expert with over 20 years of experience in the automotive sector, you bring a wealth of knowledge and proficiency in safeguarding automotive systems. You are fully familiar with critical standards such as ISO 21434 for automotive cybersecurity engineering and the ISO 27000 series for information security management. Your expertise extends to advanced threat modeling methodologies like STRIDE, and you have a deep understanding of various cybersecurity frameworks, including NIST CSF 2.0 and NIST SP 800-53 security controls. Your role involves developing and maintaining robust cybersecurity strategies, conducting thorough threat modeling and risk assessments, ensuring compliance with relevant standards, and integrating cutting-edge cybersecurity practices throughout the vehicle development lifecycle. Your comprehensive skill set positions you as a key player in mitigating risks and enhancing the security posture of automotive systems.

Given the following application description and detailed information, your task is to conduct an exhaustive threat modeling exercise. Identify the assets, determine the threats to each asset, and outline the potential consequences. Ensure your responses are tailored to reflect the detailed information provided.

Application Description: {app_input}

Detailed Information:

Vehicle Class: {vehicle_class}
Autonomous Level: {autonomous_level}
Connectivity Features: {connectivity_features}
Critical Systems: {critical_systems}
External Interfaces: {external_interfaces}
Data Types: {data_types}
Storage Locations: {storage_locations}
When providing the threat model, use a JSON formatted response with the key "threat_model". Under "threat_model", include an array of objects with the keys "Asset", "Threats", and "Potential Consequences".

Example of expected JSON response format:
  
    {{
      "threat_model": [
        {{
          "Asset": "Asset 1",
          "Threats": "Threat 1, Threat 2, ...",
          "Potential Consequences": "Example Potential Consequences 1, Example Potential Consequences 2, ..."
        }},
        {{
          "Threat Type": "Asset 2",
          "Scenario": "Threat 1, Threat 2, ...",
          "Potential Impact": "Example Potential Consequences 1, Example Potential Consequences 2, ..."
        }},
        // ... more assets
    ]
    }}
"""
    return prompt


# Function to get threat model from the GPT response.
def get_threat_model(api_key, model_name, prompt):
    client = OpenAI(api_key=api_key)

    response = client.chat.completions.create(
        model=model_name,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=4000,
    )

    # Convert the JSON string in the 'content' field to a Python dictionary
    response_content = json.loads(response.choices[0].message.content)

    return response_content
# Function to save the output model as a json file 
def save_json_to_file(data, json_path):
    # os.makedirs(os.path.dirname(json_path), exist_ok=True)
    with open(json_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)

# Function to get threat model from the Google response.
def get_threat_model_google(google_api_key, google_model, prompt):
    genai.configure(api_key=google_api_key)
    model = genai.GenerativeModel(
        google_model,
        generation_config={"response_mime_type": "application/json"})
    response = model.generate_content(prompt)
    try:
        # Access the JSON content from the 'parts' attribute of the 'content' object
        response_content = json.loads(response.candidates[0].content.parts[0].text)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {str(e)}")
        print("Raw JSON string:")
        print(response.candidates[0].content.parts[0].text)
        return None

    return response_content