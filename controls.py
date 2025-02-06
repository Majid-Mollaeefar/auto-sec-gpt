# controls.py

import json
from openai import OpenAI
import requests

def create_controls_prompt(api_key, model_name, input_file_name, output_file_name):
    client = OpenAI(api_key=api_key)

    with open(input_file_name, 'r') as file:
        data = json.load(file)

    controls_model = []

    for item in data:
        asset = item["Asset"]
        threats = item["Threats"]

        threat_list = threats.split(',')

        for threat in threat_list:
            threat = threat.strip()
            prompt = (
                f"Asset: {asset}\n"
                f"Threat: {threat}\n"
                f"""
                As a seasoned cybersecurity expert with over 25 years of experience in the automotive sector, you bring a wealth of knowledge in ISO/SAE 21434 and NIST SP 800-53 security controls. Your task is to identify appropriate security controls for the given threat related to an automotive asset.

                The output MUST be strictly in JSON format with the following keys:
                - controls_model: An array containing a single object for this threat.
                  - Threat: The identifier or name of the threat.
                  - Asset: The name of the asset.
                  - Security Controls: An array of objects, each representing a security control.
                    - control_id: Unique identifier for the control (e.g., AC-1, SC-1).
                    - control_name: The name of the security control.
                    - control_description: A brief description of what the control does.
                    - control_type: The type/category of control (e.g., Preventive, Detective, Corrective).
                    - implementation_priority: Priority level for implementing this control (High, Medium, Low).

                Please ensure that the Security Controls are provided as an array of objects, even if there's only one item.

                Example of expected JSON response format:
                ```json
                {{
                    "controls_model": [
                        {{
                            "Threat": "threat_name",
                            "Asset": "asset_name",
                            "Security Controls": [
                                {{
                                    "control_id": "AC-1",
                                    "control_name": "Access Control Policy",
                                    "control_description": "Description of the control",
                                    "control_type": "Preventive",
                                    "implementation_priority": "High"
                                }}
                            ]
                        }}
                    ]
                }}
                ```
                YOUR RESPONSE (do not add introductory text, just provide JSON formatted output):
                """
            )
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=4000,
                )

                # Parse the JSON response and add it to results
                response_content = response.choices[0].message.content
                print(f"Raw response content for threat '{threat}':\n{response_content}")

                # Clean and format the JSON response
                response_content = response_content.strip('```json').strip('```')
                
                # Fix common JSON formatting issues
                response_content = response_content.replace("'", '"')  # Replace single quotes with double quotes
                response_content = response_content.replace('\n', '')  # Remove newlines
                response_content = response_content.replace('    ', '')  # Remove extra spaces
                
                # Add missing commas between array elements
                response_content = response_content.replace('"}{"', '"},{"')
                response_content = response_content.replace('"]"', '"],"')
                response_content = response_content.replace('"}"', '"},"')
                
                # Ensure the response is valid JSON
                try:
                    response_json = json.loads(response_content)
                except json.JSONDecodeError as e:
                    print(f"Initial JSON parsing failed: {e}")
                    # Try to fix missing commas between object properties
                    response_content = response_content.replace('""', '","')
                    response_content = response_content.replace('"control_id"', ',"control_id"')
                    response_content = response_content.replace('"control_name"', ',"control_name"')
                    response_content = response_content.replace('"control_description"', ',"control_description"')
                    response_content = response_content.replace('"control_type"', ',"control_type"')
                    response_content = response_content.replace('"implementation_priority"', ',"implementation_priority"')
                    response_content = response_content.replace('"Security Controls"', ',"Security Controls"')
                    response_json = json.loads(response_content)
                # Clean the JSON content by replacing \u2019 with the correct character
                json_str = json.dumps(response_json)
                cleaned_json_str = json_str.replace("\\u2019", "'")
                cleaned_json = json.loads(cleaned_json_str)
                controls_model.append(cleaned_json['controls_model'][0])

            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON response for threat: {threat}. Error: {e}")
                print(f"Response content: {response_content}")
            except Exception as e:
                print(f"Error processing threat '{threat}': {str(e)}")

    # Save results to output file
    output_data = {"controls_model": controls_model}
    with open(output_file_name, 'w') as output_file:
        json.dump(output_data, output_file, indent=4)

def json_to_markdown_controls(output_file_name):
    with open(output_file_name, 'r') as file:
        controls_model_data = json.load(file)

    markdown_output = "## Security Controls Model\n\n"
    markdown_output += "| Asset | Threat | Control ID | Control Name | Description | Type | Priority |\n"
    markdown_output += "|-------|---------|------------|--------------|-------------|------|----------|\n"

    for control_model in controls_model_data["controls_model"]:
        asset = control_model["Asset"]
        threat = control_model["Threat"]
        
        for control in control_model["Security Controls"]:
            markdown_output += (
                f"| {asset} | {threat} | {control['control_id']} | "
                f"{control['control_name']} | {control['control_description']} | "
                f"{control['control_type']} | {control['implementation_priority']} |\n"
            )

    return markdown_output

def create_controls_prompt_local_llm(lmstudio_url, model_name, input_file_name, output_file_name):
    with open(input_file_name, 'r') as file:
        data = json.load(file)

    controls_model = []

    for item in data:
        asset = item["Asset"]
        threats = item["Threats"]
        
        threat_list = threats.split(',')
        
        for threat in threat_list:
            threat = threat.strip()
            prompt = (
                f"Asset: {asset}\n"
                f"Threat: {threat}\n"
                f"""
                As a seasoned cybersecurity expert with over 25 years of experience in the automotive sector, you bring a wealth of knowledge in ISO/SAE 21434 and NIST SP 800-53 security controls. Your task is to identify appropriate security controls for the given threat related to an automotive asset.

                The output MUST be strictly in JSON format with the following keys:
                - controls_model: An array containing a single object for this threat.
                  - Threat: The identifier or name of the threat.
                  - Asset: The name of the asset.
                  - Security Controls: An array of objects, each representing a security control.
                    - control_id: Unique identifier for the control (e.g., AC-1, SC-1).
                    - control_name: The name of the security control.
                    - control_description: A brief description of what the control does.
                    - control_type: The type/category of control (e.g., Preventive, Detective, Corrective).
                    - implementation_priority: Priority level for implementing this control (High, Medium, Low).

                Example of expected JSON response format:
                ```json
                {{
                    "controls_model": [
                        {{
                            "Threat": "threat_name",
                            "Asset": "asset_name",
                            "Security Controls": [
                                {{
                                    "control_id": "AC-1",
                                    "control_name": "Access Control Policy",
                                    "control_description": "Description of the control",
                                    "control_type": "Preventive",
                                    "implementation_priority": "High"
                                }}
                            ]
                        }}
                    ]
                }}
                ```
                YOUR RESPONSE (do not add introductory text, just provide JSON formatted output):
                """
            )

            try:
                # Prepare the data for local LLM request
                data = {
                    "model": model_name,
                    "messages": [
                        {"role": "system", "content": "You are a cybersecurity expert."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.7,
                    "max_tokens": 4096,
                    "stream": False
                }

                # Send request to local LLM instance
                response = requests.post(f"{lmstudio_url}/v1/chat/completions", json=data)

                if response.status_code == 200:
                    response_json = response.json()
                    generated_text = response_json.get("choices", [{}])[0].get("message", {}).get("content", "")
                    print(f"Raw response content for threat '{threat}':\n{generated_text}")
                    
                    # Strip any triple backticks from the response content
                    generated_text = generated_text.strip('```json').strip('```')

                    # Parse the generated JSON response
                    response_content = json.loads(generated_text)

                    # Clean the JSON content
                    json_str = json.dumps(response_content)
                    cleaned_json_str = json_str.replace("\\u2019", "'")
                    cleaned_json = json.loads(cleaned_json_str)

                    # Append the cleaned controls model data
                    controls_model.append(cleaned_json['controls_model'][0])

                else:
                    print(f"Error: Local LLM returned status code {response.status_code}")

            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON response for threat: {threat}. Error: {e}")
            except Exception as e:
                print(f"Error processing threat '{threat}': {str(e)}")

    # Save results to output file
    output_data = {"controls_model": controls_model}
    with open(output_file_name, 'w') as output_file:
        json.dump(output_data, output_file, indent=4)
