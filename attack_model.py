# attack_model.py

import json
from openai import OpenAI
import requests

def create_attack_model_prompt(api_key, model_name, input_file_name, output_file_name):
    client = OpenAI(api_key=api_key)

    with open(input_file_name, 'r') as file:
        data = json.load(file)

    attack_model = []

    for item in data:
        asset = item["Asset"]
        threats = item["Threats"]

        threat_list = threats.split(',')

        for threat in threat_list:
            threat = threat.strip()
            prompt = (
                f"Asset: {asset}\n"
                f"Threats: {threat}\n"
                f"""
                As a seasoned cybersecurity expert with over 25 years of experience in the automotive sector, you bring a wealth of knowledge and proficiency in safeguarding automotive systems. Your task is to conduct an attack model for the application scenario where for each identified threat related to an asset, identify the objectives of attackers, the attack vectors they might use, and detailed attack scenarios for each vector.

                The output MUST be strictly in JSON format with the following keys:
                - attack_model: An array containing a single object for this threat.
                  - Threat: The identifier or name of the threat.
                  - Attacker Objectives: An array of objectives the attacker aims to achieve.
                  - Attack Vectors: An array of objects, each representing an attack vector.
                    - vector_id: Unique identifier for the attack vector.
                    - vector_name: The name of the attack vector.
                    - Attack Scenarios: An array of objects, each representing an attack scenario.
                      - scenario_id: Unique identifier for the attack scenario.
                      - scenario_description: A brief description of the attack scenario.

                Please ensure that the Attack Vectors and Attack Scenarios are provided as arrays of objects, even if there's only one item.

                Example of expected JSON response format:
                ```json
                {{
                    "attack_model": [
                        {{
                        "Threat": "threat_1",
                        "Attacker Objectives": ["objective_1", "objective_2"],
                        "Attack Vectors": [
                            {{
                            "vector_id": "vector_1",
                            "vector_name": "vector_name_1",
                            "Attack Scenarios": [
                                {{
                                "scenario_id": "scenario_1",
                                "scenario_description": "description_1"
                                }}
                            ]
                            }}
                        ]
                        }} // ... more threats
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

                # Strip any triple backticks from the response content
                response_content = response_content.strip('```json').strip('```')
                
                # Ensure the response is valid JSON
                response_json = json.loads(response_content)
                # Clean the JSON content by replacing \u2019 with the correct character
                json_str = json.dumps(response_json)
                cleaned_json_str = json_str.replace("\\u2019", "'")
                cleaned_json = json.loads(cleaned_json_str)
                attack_model.append(cleaned_json['attack_model'][0])

            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON response for threat: {threat}. Error: {e}")
                print(f"Response content: {response_content}")
            except Exception as e:
                print(f"Error processing threat '{threat}': {str(e)}")

    # Save results to output file
    output_data = {"attack_model": attack_model}
    with open(output_file_name, 'w') as output_file:
        json.dump(output_data, output_file, indent=4)


# Up to here is working



# Function to convert JSON to Markdown for display.
def json_to_markdown_model(output_file_name):
    with open(output_file_name, 'r') as file:
        attack_model_data = json.load(file)

    markdown_output_attack_model = "## Attack Model\n\n"
    markdown_output_attack_model += "| Threat | Attacker Objectives | Attack Vectors and Scenarios |\n"
    markdown_output_attack_model += "|--------|---------------------|-----------------------------|\n"

    for threat_model in attack_model_data["attack_model"]:
        threat = threat_model["Threat"]
        attacker_objectives = "<br>".join([f"- {obj}" for obj in threat_model["Attacker Objectives"]])

        attack_vectors_markdown = ""
        for vector in threat_model["Attack Vectors"]:
            vector_name = vector["vector_name"]
            attack_vectors_markdown += f"**{vector_name}**<br>"
            for idx, scenario in enumerate(vector["Attack Scenarios"], 1):
                attack_vectors_markdown += f"{idx}. {scenario['scenario_description']}<br>"

        markdown_output_attack_model += f"| {threat} | {attacker_objectives} | {attack_vectors_markdown} |\n"

    return markdown_output_attack_model


# A new code for creating unified threat model with control
def normalize_threat_name(threat_name: str) -> str:
    """
    Convert threat names to a common, comparable format by
    lowercasing, stripping, and replacing spaces with underscores.
    You can refine this logic based on your data constraints.
    """
    return threat_name.lower().strip().replace(" ", "_")


def create_unified_threat_model(threats_file, attack_model_file, controls_file, output_file):
    # Load original JSON files
    with open(threats_file) as f:
        threats_data = json.load(f)

    with open(attack_model_file) as f:
        attack_model_data = json.load(f)
        
    with open(controls_file) as f:
        controls_data = json.load(f)

    # Initialize unified data
    unified_data = {"assets": []}
    
    # Process each asset in the threats JSON
    for threat_entry in threats_data:
        asset_name = threat_entry["Asset"]
        asset_threats = threat_entry["Threats"].split(", ")
        asset_consequences = threat_entry["Potential Consequences"].split(", ")

        # Create a dictionary for the asset
        asset_dict = {
            "name": asset_name,
            "threats": [],
            "consequences": asset_consequences
        }

        # For each threat string in the 'Threats' field (which may contain multiple comma-separated threats)
        for asset_threat in asset_threats:
            # Normalize the threat name from threats.json
            normalized_asset_threat = normalize_threat_name(asset_threat)

            # Search in attack_model_data for a threat with the same normalized name
            for attack in attack_model_data["attack_model"]:
                if normalize_threat_name(attack["Threat"]) == normalized_asset_threat:
                    # Find corresponding controls in controls_data
                    controls = next(
                        (
                            c["Security Controls"]
                            for c in controls_data["controls_model"]
                            if normalize_threat_name(c["Threat"]) == normalized_asset_threat
                            and c["Asset"].strip() == asset_name.strip()
                        ),
                        []
                    )

                    # Check if the threat already exists in the asset's threats list to avoid duplication
                    existing_threat = next(
                        (t for t in asset_dict["threats"] if t["name"] == asset_threat),
                        None
                    )

                    if existing_threat is None:
                        # Create new threat dictionary if it does not exist
                        threat_dict = {
                            "name": asset_threat,  # keep the original (capitalization/spaces) name
                            "objectives": attack["Attacker Objectives"],
                            "vectors": [
                                {
                                    "vector_id": vector["vector_id"],
                                    "vector_name": vector["vector_name"],
                                    "scenarios": [
                                        {
                                            "scenario_id": scenario["scenario_id"],
                                            "scenario_description": scenario["scenario_description"]
                                        }
                                        for scenario in vector["Attack Scenarios"]
                                    ]
                                }
                                for vector in attack["Attack Vectors"]
                            ],
                            "controls": controls
                        }
                        asset_dict["threats"].append(threat_dict)
                    else:
                        # If the threat already exists, merge its vectors and merge the controls
                        for vector in attack["Attack Vectors"]:
                            if not any(v["vector_id"] == vector["vector_id"] for v in existing_threat["vectors"]):
                                existing_threat["vectors"].append({
                                    "vector_id": vector["vector_id"],
                                    "vector_name": vector["vector_name"],
                                    "scenarios": [
                                        {
                                            "scenario_id": scenario["scenario_id"],
                                            "scenario_description": scenario["scenario_description"]
                                        }
                                        for scenario in vector["Attack Scenarios"]
                                    ]
                                })
                        
                        # Merge any controls from this iteration
                        # (The next() call above returns the controls for this threat)
                        existing_threat["controls"].extend(controls)

        unified_data["assets"].append(asset_dict)

    # Save the unified data into a single JSON file
    with open(output_file, 'w') as f:
        json.dump(unified_data, f, indent=4)

    print(f"Unified data has been saved into {output_file}.")




# def create_unified_threat_model(threats_file, attack_model_file, controls_file, output_file):
#     # Load original JSON files
#     with open(threats_file) as f:
#         threats_data = json.load(f)

#     with open(attack_model_file) as f:
#         attack_model_data = json.load(f)
        
#     with open(controls_file) as f:
#         controls_data = json.load(f)

#     # Initialize unified data
#     unified_data = {"assets": []}
    
#     # Process each asset in threats.json
#     for threat in threats_data:
#         asset_name = threat['Asset']
#         asset_threats = threat['Threats'].split(', ')
#         asset_consequences = threat['Potential Consequences'].split(', ')

#         # Create a dictionary for the asset
#         asset_dict = {
#             "name": asset_name,
#             "threats": [],
#             "consequences": asset_consequences
#         }

#         for asset_threat in asset_threats:
#             for attack in attack_model_data['attack_model']:
#                 if attack['Threat'] == asset_threat:
#                     # Find corresponding controls for this threat
#                     controls = next((c['Security Controls'] for c in controls_data['controls_model'] 
#                                   if c['Threat'].strip() == asset_threat.strip() and 
#                                   c['Asset'].strip() == asset_name.strip()), [])
                    
#                     # Check if the threat already exists in the asset's threats list to avoid duplication
#                     existing_threat = next((t for t in asset_dict['threats'] if t['name'] == asset_threat), None)
#                     if existing_threat is None:
#                         # Create new threat dictionary if it does not exist
#                         threat_dict = {
#                             "name": asset_threat,
#                             "objectives": attack['Attacker Objectives'],
#                             "vectors": [{
#                                 "vector_id": vector['vector_id'],
#                                 "vector_name": vector['vector_name'],
#                                 "scenarios": [{
#                                     "scenario_id": scenario['scenario_id'],
#                                     "scenario_description": scenario['scenario_description']
#                                 } for scenario in vector['Attack Scenarios']]
#                             } for vector in attack['Attack Vectors']],
#                             "controls": controls
#                         }
#                         asset_dict["threats"].append(threat_dict)
#                     else:
#                         # If the threat already exists, merge its vectors and controls
#                         for vector in attack['Attack Vectors']:
#                             if not any(v['vector_id'] == vector['vector_id'] for v in existing_threat['vectors']):
#                                 existing_threat['vectors'].append({
#                                     "vector_id": vector['vector_id'],
#                                     "vector_name": vector['vector_name'],
#                                     "scenarios": [{
#                                         "scenario_id": scenario['scenario_id'],
#                                         "scenario_description": scenario['scenario_description']
#                                     } for scenario in vector['Attack Scenarios']]
#                                 })
#                         existing_threat['controls'].extend(attack.get('controls', []))

#         unified_data["assets"].append(asset_dict)

#     # Save the unified data into a single JSON file
#     with open(output_file, 'w') as f:
#         json.dump(unified_data, f, indent=4)

#     print(f"Unified data has been saved into {output_file}.")


#----------------------------------------------
#-----------Local LLM--------------------------
def create_attack_model_prompt_local_llm(lmstudio_url, model_name, input_file_name, output_file_name):
    # Load input data from file
    with open(input_file_name, 'r') as file:
        data = json.load(file)

    attack_model = []

    for item in data:
        asset = item["Asset"]
        threats = item["Threats"]
        
        threat_list = threats.split(',')
        
        for threat in threat_list:
            threat = threat.strip()
            prompt = (
                f"Asset: {asset}\n"
                f"Threats: {threat}\n"
                f"""
                As a seasoned cybersecurity expert with over 25 years of experience in the automotive sector, your task is to conduct an attack model for the application scenario where for each identified threat related to an asset, identify the objectives of attackers, the attack vectors they might use, and detailed attack scenarios for each vector.

                The output MUST be strictly in JSON format with the following keys:
                - attack_model: An array containing a single object for this threat.
                  - Threat: The identifier or name of the threat.
                  - Attacker Objectives: An array of objectives the attacker aims to achieve.
                  - Attack Vectors: An array of objects, each representing an attack vector.
                    - vector_id: Unique identifier for the attack vector.
                    - vector_name: The name of the attack vector.
                    - Attack Scenarios: An array of objects, each representing an attack scenario.
                      - scenario_id: Unique identifier for the attack scenario.
                      - scenario_description: A brief description of the attack scenario.

                Example of expected JSON response format:
                ```json
                {{
                    "attack_model": [
                        {{
                        "Threat": "threat_1",
                        "Attacker Objectives": ["objective_1", "objective_2"],
                        "Attack Vectors": [
                            {{
                            "vector_id": "vector_1",
                            "vector_name": "vector_name_1",
                            "Attack Scenarios": [
                                {{
                                "scenario_id": "scenario_1",
                                "scenario_description": "description_1"
                                }}
                            ]
                            }}
                        ]
                        }} // ... more threats
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

                    # Append the cleaned attack model data
                    attack_model.append(cleaned_json['attack_model'][0])

                else:
                    print(f"Error: Local LLM returned status code {response.status_code}")

            except json.JSONDecodeError as e:
                print(f"Failed to decode JSON response for threat: {threat}. Error: {e}")
            except Exception as e:
                print(f"Error processing threat '{threat}': {str(e)}")

    # Save results to output file
    output_data = {"attack_model": attack_model}
    with open(output_file_name, 'w') as output_file:
        json.dump(output_data, output_file, indent=4)


# def create_unified_attack_model(threats_file, attack_model_file, output_file):
#     """
#     Load threats and attack model JSON files, merge the data, and save unified data to an output file.

#     Parameters:
#     threats_file (str): Path to the threats JSON file.
#     attack_model_file (str): Path to the attack model JSON file.
#     output_file (str): Path where the unified JSON file will be saved.
#     """
#     # Load original JSON files
#     with open(threats_file, 'r') as f:
#         threats_data = json.load(f)

#     with open(attack_model_file, 'r') as f:
#         attack_model_data = json.load(f)

#     # Function to create unified data for each asset
#     def create_unified_data(threats, attack_model):
#         unified_data = {"assets": []}

#         # Process threats and merge with attack model data
#         for threat in threats:
#             asset_name = threat['Asset']
#             asset_threats = threat['Threats'].split(', ')
#             asset_consequences = threat['Potential Consequences'].split(', ')

#             # Create a dictionary for the asset
#             asset_dict = {
#                 "name": asset_name,
#                 "threats": [],
#                 "consequences": asset_consequences
#             }

#             for asset_threat in asset_threats:
#                 for attack in attack_model:
#                     if attack['Threat'] == asset_threat:
#                         threat_dict = {
#                             "name": asset_threat,
#                             "objectives": attack['Attacker Objectives'],
#                             "vectors": [{
#                                 "vector_id": vector['vector_id'],
#                                 "vector_name": vector['vector_name'],
#                                 "scenarios": [{
#                                     "scenario_id": scenario['scenario_id'],
#                                     "scenario_description": scenario['scenario_description']
#                                 } for scenario in vector['Attack Scenarios']]
#                             } for vector in attack['Attack Vectors']],
#                             "controls": attack.get('controls', [])
#                         }
#                         asset_dict["threats"].append(threat_dict)

#             unified_data["assets"].append(asset_dict)

#         return unified_data

#     # Create unified data
#     unified_data = create_unified_data(threats_data, attack_model_data['attack_model'])

#     # Save the unified data into a single JSON file
#     with open(output_file, 'w') as f:
#         json.dump(unified_data, f, indent=4)

