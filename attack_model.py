import json
import os
from openai import OpenAI
import re

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

                # Strip any triple backticks from the response content
                response_content = response_content.strip('```json').strip('```')
                
                # Ensure the response is valid JSON
                response_json = json.loads(response_content)
                attack_model.append(response_json['attack_model'][0])

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



def create_unified_attack_model(threats_file, attack_model_file, output_file):
    """
    Load threats and attack model JSON files, merge the data, and save unified data to an output file.

    Parameters:
    threats_file (str): Path to the threats JSON file.
    attack_model_file (str): Path to the attack model JSON file.
    output_file (str): Path where the unified JSON file will be saved.
    """
    # Load original JSON files
    with open(threats_file, 'r') as f:
        threats_data = json.load(f)

    with open(attack_model_file, 'r') as f:
        attack_model_data = json.load(f)

    # Function to create unified data for each asset
    def create_unified_data(threats, attack_model):
        unified_data = {"assets": []}

        # Process threats and merge with attack model data
        for threat in threats:
            asset_name = threat['Asset']
            asset_threats = threat['Threats'].split(', ')
            asset_consequences = threat['Potential Consequences'].split(', ')

            # Create a dictionary for the asset
            asset_dict = {
                "name": asset_name,
                "threats": [],
                "consequences": asset_consequences
            }

            for asset_threat in asset_threats:
                for attack in attack_model:
                    if attack['Threat'] == asset_threat:
                        threat_dict = {
                            "name": asset_threat,
                            "objectives": attack['Attacker Objectives'],
                            "vectors": [{
                                "vector_id": vector['vector_id'],
                                "vector_name": vector['vector_name'],
                                "scenarios": [{
                                    "scenario_id": scenario['scenario_id'],
                                    "scenario_description": scenario['scenario_description']
                                } for scenario in vector['Attack Scenarios']]
                            } for vector in attack['Attack Vectors']],
                            "controls": attack.get('controls', [])
                        }
                        asset_dict["threats"].append(threat_dict)

            unified_data["assets"].append(asset_dict)

        return unified_data

    # Create unified data
    unified_data = create_unified_data(threats_data, attack_model_data['attack_model'])

    # Save the unified data into a single JSON file
    with open(output_file, 'w') as f:
        json.dump(unified_data, f, indent=4)

    print(f"Unified data has been saved into {output_file}.")


# import google.generativeai as genai
# import json
# import os
# from openai import OpenAI
# import re


# def create_attack_model_prompt(api_key, model_name, input_file_name, output_file_name):
#     client = OpenAI(api_key=api_key)

#         # Read the JSON file
#     with open(input_file_name, 'r') as file:
#         data = json.load(file)

#     results = []

#     for item in data:
#         asset = item["Asset"]
#         threats = item["Threats"]
        
#         threat_list = threats.split(',')

#         for threat in threat_list:
#             threat = threat.strip()
#             prompt = (
#                 f"Asset: {asset}\n"
#                 f"Threats: {threat}\n"
#                 f""" 
#                 As a seasoned cybersecurity expert with over 25 years of experience in the automotive sector, you bring a wealth of knowledge and proficiency in safeguarding automotive systems. Your task is to conduct an attack model for the application scenario where for each identified threat related to an asset, identify the objectives of attackers, the attack vectors they might use, and detailed attack scenarios for each vector. 
#                 The output should be structured in JSON format with the following keys:
#                 attack_model: An array containing multiple objects, each representing a threat.
#                 Threat: The identifier or name of the threat.
#                 Attacker Objectives: An array of objectives the attacker aims to achieve.
#                 Attack Vectors: An array of objects, each representing an attack vector.
#                 vector_id: Unique identifier for the attack vector.
#                 vector_name: The name of the attack vector.
#                 Attack Scenarios: An array of objects, each representing an attack scenario.
#                 scenario_id: Unique identifier for the attack scenario.
#                 scenario_description: A brief description of the attack scenario.

#                 Example of expected JSON response format:          
#                 {{
#                 "attack_model": [
#                     {{
#                     "Threat": "threat_1",
#                     "Attacker Objectives": ["objective_1", "objective_2"],
#                     "Attack Vectors": [
#                         {{
#                         "vector_id": "vector_1",
#                         "vector_name": "vector_name_1",
#                         "Attack Scenarios": [
#                             {{
#                             "scenario_id": "scenario_1",
#                             "scenario_description": "description_1"
#                             }},
#                             {{
#                             "scenario_id": "scenario_2",
#                             "scenario_description": "description_2"
#                             }}
#                         ]
#                         }},
#                         {{
#                         "vector_id": "vector_2",
#                         "vector_name": "vector_name_2",
#                         "Attack Scenarios": [
#                             {{
#                             "scenario_id": "scenario_3",
#                             "scenario_description": "description_3"
#                             }}
#                         ]
#                         }}
#                     ]
#                     }}, ... more threats
#                 ]
#                 }}
                
#                 YOUR RESPONSE (do not add introductory text, just provide JSON formatted output)                       
#                 """)
#             response = client.chat.completions.create(
#                 model=model_name,
#                 messages=[
#                     {"role": "system", "content": "You are a cybersecurity expert."},
#                     {"role": "user", "content": prompt}
#                 ],
#                 max_tokens=4000,
#             )

#             response_content = response.choices[0].message.content
            
#             # Extract the relevant information from the response
#             attacker_objectives = clean_text(extract_section(response_content, "Attacker Objectives"))
#             attack_vectors = extract_section(response_content, "Attack Vectors")

#             attack_vectors_list = parse_attack_vectors(attack_vectors)

#             results.append({
#                 "Threat": threat,
#                 "Attacker Objectives": [attacker_objectives],  # Ensure this is a list
#                 "Attack Vectors": attack_vectors_list,
#             })

#     output = {
#         "attack_model": results
#     }

#     # Write the results to the output file
#     with open(output_file_name, 'w') as outfile:
#         json.dump(output, outfile, indent=4)


# def extract_section(text, section_title):
#     """
#     Extracts a section from the response text based on the section title.

#     Parameters:
#     text (str): The response text from which to extract the section.
#     section_title (str): The title of the section to extract.

#     Returns:
#     str: The extracted section content.
#     """
#     section_start = text.find(section_title)
#     if (section_start == -1):
#         return ""
    
#     section_start += len(section_title) + 1
#     section_end = text.find("\n", section_start)
#     if section_end == -1:
#         section_end = len(text)
    
#     return text[section_start:section_end].strip()


# def clean_text(text):
#     """
#     Cleans the extracted text to remove unwanted characters.

#     Parameters:
#     text (str): The text to be cleaned.

#     Returns:
#     str: The cleaned text.
#     """
#     text = re.sub(r'[\:\[\]\"\,]', '', text)
#     text = re.sub(r'\\u2019', "'", text)  # Replace unicode apostrophe with normal apostrophe
#     text = text.replace('\\', '')  # Remove backslashes

#     return text if text else "Information not provided."


# def parse_attack_vectors(text):
#     """
#     Parses the attack vectors from text to a list of dictionaries.

#     Parameters:
#     text (str): The attack vectors text to be parsed.

#     Returns:
#     list: The parsed list of attack vectors.
#     """
#     vectors = []
#     vector_lines = text.split('\n')
#     for line in vector_lines:
#         parts = line.split(':', 1)
#         if len(parts) == 2:
#             vector_name = parts[0].strip()
#             scenarios_text = parts[1].strip()
#             scenarios = parse_attack_scenarios(scenarios_text)
#             vectors.append({
#                 "vector_name": vector_name,
#                 "scenarios": scenarios
#             })
#     return vectors


# def parse_attack_scenarios(text):
#     """
#     Parses the attack scenarios from text to a list of dictionaries.

#     Parameters:
#     text (str): The attack scenarios text to be parsed.

#     Returns:
#     list: The parsed list of attack scenarios.
#     """
#     scenarios = []
#     scenario_lines = text.split('\n')
#     for line in scenario_lines:
#         parts = line.split(' ', 1)
#         if len(parts) == 2:
#             scenarios.append({
#                 "scenario_id": parts[0].strip(),
#                 "scenario_description": parts[1].strip()
#             })
#     return scenarios


# # Function to convert JSON to Markdown for display.
# def json_to_markdown_model(output_file_name):
#     with open(output_file_name, 'r') as file:
#         attack_model_data = json.load(file)

#     markdown_output_attack_model = "## Attack Model\n\n"

#     markdown_output_attack_model += "| Threat | Attacker Objectives | Attack Vectors and Scenarios |\n"
#     markdown_output_attack_model += "|--------|---------------------|-----------------------------|\n"

#     for attack in attack_model_data["attack_model"]:
#         threat = attack['Threat']
#         objectives = ", ".join(attack['Attacker Objectives'])
#         attack_vectors = attack['Attack Vectors']

#         vector_scenario_pairs = []
#         for vector in attack_vectors:
#             if isinstance(vector, dict):  # Check if 'vector' is a dictionary
#                 try:
#                     vector_name = vector['vector_name']
#                 except KeyError:
#                     print(f"Warning: 'vector_name' missing for vector in attack {attack['Threat']}. Skipping this vector.")
#                     continue  
#             else:
#                 print(f"Warning: Unexpected data type for vector in attack {attack['Threat']}. Skipping this vector.")
#                 continue  # Skip to the next vector

#             scenarios = vector['scenarios']

#             scenario_descriptions = []
#             for scenario in scenarios:
#                 scenario_id = scenario['scenario_id']
#                 scenario_description = scenario['scenario_description']
#                 scenario_descriptions.append(f"{scenario_id}: {scenario_description}")

#             scenarios_str = "<br>".join(scenario_descriptions)
#             vector_scenario_pairs.append(f"{vector_name}:<br>{scenarios_str}")

#         attack_vectors_str = "<br><br>".join(vector_scenario_pairs)
#         markdown_output_attack_model += f"| {threat} | {objectives} | {attack_vectors_str} |\n"

#     return markdown_output_attack_model