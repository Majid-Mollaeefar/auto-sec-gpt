# main.py
import os
import streamlit as st
import streamlit.components.v1 as components
import json
from datetime import datetime 
from util.sidebar import configure_sidebar, render_header
from tabs.threat_model import (
    create_threat_model_prompt,
    get_threat_model,
    json_to_markdown,
    save_json_to_file,
    get_installed_models,
    get_threat_model_llmlocal,
)
from tabs.attack_model import create_attack_model_prompt, json_to_markdown_model, create_unified_threat_model, create_attack_model_prompt_local_llm
from tabs.attack_graph import create_attack_graph, display_attackgraph_html_files
from tabs.controls import create_controls_prompt, json_to_markdown_controls, create_controls_prompt_local_llm
import tabs.likelihood_assessment_customized as customized
import tabs.likelihood_assessment_full as full
import tabs.impact_assessment as impact_assessment
from tabs.risk_computation import risk_evaluation, display_prioritized_risks, load_impact_assessment
from tabs.report import download_file, load_saved_attack_graphs, display_screenshots 
import pandas as pd
from tabs.weakness import (
    flatten_field, load_attack_patterns, load_threat_scenarios,
    compute_similarities, generate_updated_threat_scenario,
    generate_updated_threat_scenario_llmlocal,  
    save_scenario_data, clean_text_for_markdown
)

# ------------------ Helper Functions ------------------ #


# Function to get user input for the application description and key details
def get_input():
    input_text = st.text_area(
        label="Describe the application to be modelled",
        placeholder="Enter your application details...",
        height=280,
        key="app_desc",
        help="Please provide a detailed description of the application, including the purpose of the application, the technologies used, and any other relevant information.",
    )

    st.session_state["app_input"] = input_text

    return input_text


# ------------------ Streamlit UI Configuration ------------------ #
# Define the configuration content for the theme
config_content = """
[theme]
primaryColor="#f56b6b"
backgroundColor="#273750"
secondaryBackgroundColor="#081324"
textColor="#ffffff"
font="serif"
"""
# Create the .streamlit directory if it does not exist
os.makedirs(".streamlit", exist_ok=True)

# Write the configuration content to the config.toml file
with open(".streamlit/config.toml", "w") as config_file:
    config_file.write(config_content)
st.set_page_config(
    page_title="AutoSecGPT",
    page_icon=":racing_car:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ------------------ Sidebar ------------------ #

st.sidebar.image("util\\logo.png")

headers = [
    ("How to use AutoSecGPT", "#f56b6b"),
    ("About", "#f56b6b"),
    ("Example of Application Description", "#f56b6b")
]
configure_sidebar(headers)

# Add instructions on how to use the app to the sidebar
render_header(0)
with st.sidebar:
   
    # Add model selection input field to the sidebar
    model_provider = st.selectbox(
        "Select your preferred model provider:",
        ["OpenAI API","Local LLM"],
        key="model_provider",
        help="Select the model provider you would like to use. This will determine the models available for selection.",
    )

    if model_provider == "OpenAI API":
        st.markdown(
            """
            1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) and chosen model below 🔑
            2. Provide details of the application that you would like to model together with additional determined information  📝
            3. Generate a threat list, model attacks, generate and visualize asset-based attack graphs for your application 🚀
            """
        )
        # Add OpenAI API key input field to the sidebar
        openai_api_key = st.text_input(
            "Enter your OpenAI API key:",
            type="password",
            help="You can find your OpenAI API key on the [OpenAI dashboard](https://platform.openai.com/account/api-keys).",
        )

        # Add model selection input field to the sidebar
        selected_model = st.selectbox(
            "Select the model you would like to use:",
            ["o1","o3-mini","gpt-4o-mini","gpt-4o", "gpt-4-turbo", "gpt-4"],
            key="selected_model",
            help="OpenAI have moved to continuous model upgrades so `gpt-4`, `gpt-4-turbo`, `gpt-4o` point to the latest available version of each model.",
        )
    elif model_provider == "Local LLM":
        st.markdown(
            """
            1. Enter the port for your local LMstudio instance below 🔑
            2. Provide details of the application that you would like to model together with additional determined information  📝
            3. Generate a threat list, model attacks, generate and visualize asset-based attack graphs for your application 🚀
            """
        )
        # Add LMstudio port input field to the sidebar
        lmstudio_port = st.text_input(
            "Enter the LMstudio port:",
            "7860",
            help="Enter the port number where your local LMstudio instance is running.",
        )

        # Fetch the list of installed models
        lmstudio_url = f"http://127.0.0.1:{lmstudio_port}"
        installed_models = get_installed_models(lmstudio_url)

        if not installed_models:
            st.error("No models found or LMstudio is not running. Please check LMstudio and try again.")
        else:
            # Display the list of installed models
            model_names = [model["id"] for model in installed_models]
            selected_model = st.selectbox("Select the model you would like to use:", model_names)
        
    
    st.markdown("""---""")

# Add "About" section to the sidebar
render_header(1)
with st.sidebar:
    st.markdown(
        "Welcome to AutoSecGPT, an AI-powered tool designed to help teams produce better threat models for their applications."
    )
    st.markdown(
        "The ISO/SAE 21434 Road Vehicles—Cybersecurity Engineering standard defines the responsibilities for various groups during different stages of automotive product development. The standard requires a commitment from executive management to product development with a focus on cybersecurity engineering."            
    )
    st.markdown(
        "ISO ISO/SAE emphasizes identifying and assessing cybersecurity risks, helping to anticipate and prepare for potential attack scenarios. Threat modelling is a key activity in the software development lifecycle, but is often overlooked or poorly executed. AutoSecGPT aims to help security teams."
    )
    st.markdown(
        "Created by [Majid Mollaeefar](https://www.linkedin.com/in/majid-mollaeefar/)."
    )
    st.markdown("""---""")


# Add "Example Application Description" section to the sidebar
render_header(2)
with st.sidebar:
    st.markdown(
        "Below is an example application description that you can use to test AutoSecGPT tool:"
    )
    st.code(
            """
            A new electric car model, features advanced autonomous
            driving capabilities and an integrated infotainment system. 
            The vehicle connects to various external networks, 
            such as GPS, mobile apps, and charging stations.
            """,
            language="md"
    )

# ------------------ Main App UI ------------------ #


tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(["Threat Model", "Attack Model", "Security Controls", "Attack Graph", "Risk Assessment", "CAPEC Analysis","Report"])

with tab1:
    st.markdown(
        """
        ISO 21434 emphasizes identifying and assessing cybersecurity risks, helping to anticipate and prepare for potential attack scenarios.
        Use this tab to conduct a comprehensive threat modeling exercise for your automotive application. 
        Identify assets, evaluate associated threats, and assess potential consequences. 
        Document and download your findings in a structured JSON and Markdown table to enhance the security posture of your system.
        """
    )
    st.markdown("""---""")

    # Two column layout for the main app content
    col1, col2, col3 = st.columns([1, 1, 1])

    # If model provider is OpenAI API and the model is gpt-4-turbo
    with col1:
        app_input = get_input()
        if "app_input" not in st.session_state:
            st.session_state["app_input"] = app_input
        # Create input fields for additional details
    with col2:
        # st.subheader("Vehicle Specifics")
        vehicle_class = st.selectbox(
            "Vehicle Class",
            ["Passenger Car", "Commercial Vehicle", "Motorcycle", "Other"],
        )
        autonomous_level = st.selectbox(
            "Autonomous Level",
            [
                "SAE Level 0",
                "SAE Level 1",
                "SAE Level 2",
                "SAE Level 3",
                "SAE Level 4",
                "SAE Level 5",
            ],
        )
        connectivity_features = st.multiselect(
            "Connectivity Features",
            [
                "V2X Communication",
                "Cellular Connectivity",
                "Wi-Fi",
                "Bluetooth",
                "Other",
            ],
        )
        # st.subheader("System Specifics")
        critical_systems = st.multiselect(
            "Critical Systems",
            [
                "Braking System",
                "Steering System",
                "Powertrain",
                "ADAS",
                "Infotainment",
                "Other",
            ],
        )

    with col3:
        external_interfaces = st.multiselect(
            "External Interfaces",
            [
                "OBD-II Port",
                "USB Ports",
                "Mobile App Integration",
                "Cloud Services",
                "Other",
            ],
        )
        # st.subheader("Data Storage")
        data_types = st.multiselect(
            "Types of Data Stored",
            [
                "Location Data",
                "Driving Habits",
                "Personal Information",
                "Vehicle Diagnostics",
                "Multimedia Content",
                "Other",
            ],
        )
        storage_locations = st.multiselect(
            "Storage Locations",
            [
                "In-Vehicle Storage",
                "Cloud Storage",
                "Mobile App",
                "Manufacturer Servers",
                "Third-Party Services",
                "Other",
            ],
        )
        # st.subheader("Threat Actor Information")
        # potential_threat_actors = st.multiselect("Potential Threat Actors", ["Script Kiddies", "Hacktivists", "Organized Crime", "Nation-States", "Disgruntled Employees", "Other"])

    # ------------------ Threat Model Generation ------------------ #

    # Create a submit button for Threat Modelling
    threat_model_submit_button = st.button(label="Generate Threat Model")

    # If the Generate Threat Model button is clicked and the user has provided an application description
    if threat_model_submit_button and st.session_state.get("app_input"):
        app_input = st.session_state["app_input"]  # Retrieve from session state

        # Generate the prompt using the create_prompt function
        threat_model_prompt = create_threat_model_prompt(
            app_input,
            vehicle_class,
            autonomous_level,
            connectivity_features,
            critical_systems,
            external_interfaces,
            data_types,
            storage_locations,
        )
        # print(threat_model_prompt)
        # Show a spinner while generating the threat model
        with st.spinner("Analysing potential threats..."):
            max_retries = 5
            retry_count = 0
            while retry_count < max_retries:
                try:
                    # Call the relevant get_threat_model function with the generated prompt
                    if  model_provider == "OpenAI API":
                        model_output = get_threat_model(
                            openai_api_key, selected_model, threat_model_prompt
                        )
                    elif model_provider == "Local LLM":
                        model_output = get_threat_model_llmlocal (
                            lmstudio_url, selected_model, threat_model_prompt
                        )

                    # Access the threat model from the parsed content
                    threat_model = model_output.get("threat_model")

                    # Save the threat model to the session state for later use in mitigations
                    st.session_state["threat_model"] = threat_model
                    break  # Exit the loop if successful
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        st.error(
                            f"Error generating threat model after {max_retries} attempts: {e}"
                        )
                        threat_model = []
                    else:
                        st.warning(
                            f"Error generating threat model. Retrying attempt {retry_count+1}/{max_retries}..."
                        )

        # Convert the threat model JSON to Markdown
        markdown_output = json_to_markdown(threat_model)
        st.session_state["threat_model_markdown"] = markdown_output
        # Save threat model as a JSON file in defined path
        # Get the current working directory
        base_path = os.getcwd()
        json_path = os.path.join(base_path, ".files\\threats.json")
        save_json_to_file(threat_model, json_path)

        # Display the threat model in Markdown
        st.markdown(markdown_output)

        # Add a button to allow the user to download the output as a Markdown file
        st.download_button(
            label="Download Threat Model",
            data=markdown_output,  # Use the Markdown output
            file_name="v-gpt_threat_model.md",
            mime="text/markdown",
        )

# If the submit button is clicked and the user has not provided an application description
if threat_model_submit_button and not st.session_state.get("app_input"):
    st.error("Please enter your application details before submitting.")

# ------------------ Attack Model ------------------- #

with tab2:
    st.markdown(
        """
        This tab provides an attack model based on identified threats for each asset and investigates scenarios of how the attacks might happen in the system. 
        The structure of the attack model includes a detailed breakdown of each threat, specifying the attack vectors and scenarios. Each identified threat lists the attacker objectives, followed by various attack vectors.
        """
    )
    st.markdown("""---""")

    if "attack_model_generated" not in st.session_state:
        st.session_state.attack_model_generated = False

    attack_model_submit_button = st.button(label="Generate Attack Model")
    if attack_model_submit_button or st.session_state.attack_model_generated:
        base_path = os.getcwd()
        input_file_name = os.path.join(base_path, ".files\\threats.json")
        # api_key = openai_api_key  
        output_file_name = os.path.join(base_path, ".files\\attack_model.json")
        # model_name = selected_model  

        if not os.path.exists(output_file_name):
            with st.spinner("Analyzing potential attacks..."):
                max_retries = 5
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        if model_provider == "OpenAI API":
                            api_key = openai_api_key 
                            model_name = selected_model
                            create_attack_model_prompt(
                                api_key, model_name, input_file_name, output_file_name
                            )
                            break
                        elif model_provider == "Local LLM":
                            lmstudio_url = lmstudio_url
                            model_name = selected_model
                            create_attack_model_prompt_local_llm(
                                lmstudio_url, model_name, input_file_name, output_file_name
                                )
                            break
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"Error generating attack model after {max_retries} attempts: {e}"
                            )
                            break
                        else:
                            st.warning(
                                f"Error generating attack model. Retrying attempt {retry_count}/{max_retries}..."
                            )

        st.session_state.attack_model_generated = True
        # unified_output_file_name = os.path.join(base_path, ".files\\unified_attack_model.json")
        # create_unified_threat_model(input_file_name, output_file_name, unified_output_file_name)
        # Convert the threat model JSON to Markdown
        markdown_output_attack_model = json_to_markdown_model(output_file_name)
        st.session_state["attack_model"] = markdown_output_attack_model
        # Display the attack model in Markdown
        st.markdown(markdown_output_attack_model, unsafe_allow_html=True)

# ------------------ Security Controls ------------------- #

with tab3:
    st.markdown(
        """
        This tab identifies appropriate security controls for each identified threat based on ISO/SAE 21434 and NIST SP 800-53 standards. 
        The controls are categorized by type (Preventive, Detective, and Corrective) and prioritized for implementation.
        Each control includes a detailed description and implementation priority to help guide the security hardening process.
        """
    )
    st.markdown("""---""")

    if "controls_generated" not in st.session_state:
        st.session_state.controls_generated = False

    controls_submit_button = st.button(label="Generate Security Controls")
    if controls_submit_button or st.session_state.controls_generated:
        base_path = os.getcwd()
        input_file_name = os.path.join(base_path, ".files\\threats.json")
        output_file_name = os.path.join(base_path, ".files\\controls.json")
        unified_output_file_name = os.path.join(base_path, ".files\\unified_attack_model.json")

        if not os.path.exists(output_file_name):
            with st.spinner("Analyzing and generating security controls..."):
                max_retries = 5
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        if model_provider == "OpenAI API":
                            api_key = openai_api_key 
                            model_name = selected_model
                            create_controls_prompt(
                                api_key, model_name, input_file_name, output_file_name
                            )
                            break
                        elif model_provider == "Local LLM":
                            create_controls_prompt_local_llm(
                                lmstudio_url, selected_model, input_file_name, output_file_name
                            )
                            break
                    except Exception as e:
                        retry_count += 1
                        if retry_count == max_retries:
                            st.error(
                                f"Error generating security controls after {max_retries} attempts: {e}"
                            )
                            break
                        else:
                            st.warning(
                                f"Error generating security controls. Retrying attempt {retry_count}/{max_retries}..."
                            )

        st.session_state.controls_generated = True

        # Create unified model with controls
        attack_model_file = os.path.join(base_path, ".files\\attack_model.json")
        create_unified_threat_model(input_file_name, attack_model_file, output_file_name, unified_output_file_name)

        # Convert the controls to Markdown and display
        markdown_output_controls = json_to_markdown_controls(output_file_name)
        st.session_state["security_controls"] = markdown_output_controls
        st.markdown(markdown_output_controls, unsafe_allow_html=True)

        # Add download button for the controls
        st.download_button(
            label="Download Security Controls",
            data=markdown_output_controls,
            file_name="security_controls.md",
            mime="text/markdown",
        )

# ------------------ Attack Graph ------------------- #
with tab4:
    st.markdown(
        """
        This tab visualizes the attack graph for each asset, illustrating the relationships between assets, threats, attack vectors, and scenarios. The graph dynamically displays interconnected nodes, detailing the progression from initial threats to potential attack scenarios and corresponding controls. This enables a comprehensive analysis of potential attack paths.
    To use this tab:
    1) Select an asset from the dropdown list.
    2) Click on each node to generate and view related threats, attack vectors, and scenarios.
    3) In the Scenario Detail box, you can add or remove scenarios for further risk assessment.
    4) After selecting scenarios for each asset, click on 'Selection Completed'. A JSON file will be downloaded, which can be used for the Risk Assessment process.
        """
    )
    st.markdown("""---""")

    # Specify the path to your attack_model JSON file (unified version of attack_model)
    base_path = os.getcwd()
    unified_attack_model_path = os.path.join(base_path, ".files\\unified_attack_model.json")

    generate_graphs_button = st.button("Generate Attack Graphs")

    if generate_graphs_button:
        if not os.path.exists(unified_attack_model_path):
            st.error("Unified attack model JSON file does not exist. Please generate the controls first in the 'Security Controls' tab.")
        else:
            # Load data directly from the JSON file
            try:
                with open(unified_attack_model_path, "r") as file:
                    data = json.load(file)
            except Exception as e:
                st.error(f"Error loading unified attack model JSON file: {e}")
                st.stop()

            # Create the output directory if it doesn't exist where the HTML data will be saved
            output_dir = os.path.join(base_path, ".files\\.attackgraph")
            os.makedirs(output_dir, exist_ok=True)

            # Create attack graphs for each asset in the JSON file
            try:
                with st.spinner("Generating attack graphs..."):
                    graph_paths = []
                    for asset in data["assets"]:
                        output_path = create_attack_graph(asset, output_dir)
                        graph_paths.append(output_path)
                    
                    # Save graph paths to session state
                    st.session_state['graph_paths'] = graph_paths
                st.success("Attack graphs generated successfully.")
            except Exception as e:
                st.error(f"Error creating attack graphs: {e}")
                st.stop()

    # If graphs have been generated, display the assets dropdown and graphs
    if 'graph_paths' in st.session_state:
        display_attackgraph_html_files(os.path.join(base_path, ".files\\.attackgraph"))



# ------------------ Risk Assessment ------------------- #

# Initialize session state for tabs and assessments
if "likelihood_assessment_complete" not in st.session_state:
    st.session_state.likelihood_assessment_complete = False
if "impact_assessment_ready" not in st.session_state:
    st.session_state.impact_assessment_ready = False

def check_likelihood_assessment_complete():
    if impact_assessment.likelihood_assessment_file_exists():
        st.session_state.impact_assessment_ready = True
    else:
        st.session_state.impact_assessment_ready = False

with tab5:
    st.markdown(
        """
        This tab performs a risk assessment. You must first complete the likelihood assessment, and then proceed to the impact assessment.
        """
    )


    tabs = st.tabs(["Likelihood Assessment", "Impact Assessment", "Risk Evaluation"])

    # Likelihood Assessment Tab
    with tabs[0]:
        st.markdown(
        """
        First step of our risk assessment is to determine the likelihood level of each attack scenario, based on defined a set of likelihood factors.
        """
         )

        st.markdown("---")

        likelihood_assessment_option = st.radio(
            "Select Likelihood Assessment Option:",
            ["Customized Scenario Selection", "Full Scenario"],
            key="likelihood_assessment_radio"
        )

        if likelihood_assessment_option == "Customized Scenario Selection":
            customized.likelihood_assessment_customized(key="customized")
        elif likelihood_assessment_option == "Full Scenario":
            full.likelihood_assessment_full()

        if st.session_state.likelihood_assessment_complete:
            st.success("Likelihood Assessment is complete. You can now proceed to Impact Assessment.")
            check_likelihood_assessment_complete()

    # Impact Assessment Tab
    with tabs[1]:
        st.markdown(
        """
        Second step is to determine the impact level of each attack scenario, based on defined a set of impact factors.
        """
         )

        st.markdown("---")
        if st.session_state.impact_assessment_ready:
            impact_assessment.impact_assessment()
        else:
            st.write("Complete the Likelihood Assessment first.")

    # Risk Evaluation Tab
    with tabs[2]:
        st.markdown(
        """
        The third step is to evaluate the risk levels. Click the button below to compute the risk evaluation.
        """
        )

        st.markdown("---")
        impact_data = load_impact_assessment()
        if impact_data is None:
            st.write("Complete the Likelihood and Impact Assessments first.")
        else:
            st.write("You can now perform the Risk Evaluation based on the completed assessments.")
            if st.button("Risk Computation"):
                st.spinner("The risk is computing...")
                eval_result = risk_evaluation()
                st.session_state["risk_evaluation"] = eval_result
                risk_table = display_prioritized_risks()
                st.session_state["risk_assessment_table"] = risk_table

        # st.markdown("---")
        # if st.button("Show Prioritized Risks"):
        #     display_prioritized_risks()


# ------------------ CAPEC Pattern ------------------- #
with tab6:
    st.markdown(
        """
        This tab offers an alternative view of attacks by analyzing the previously identified threat scenarios against the CAPEC (Common Attack Pattern Enumeration and Classification) dataset. 
        An NLP technique is used to match the threat scenarios with CAPEC patterns and to suggest updated scenarios along with appropriate mitigation strategies. 
        First, select a threat scenario (or choose ALL) and adjust the similarity threshold, then click 'Check Similarities'. After the results are displayed, you can either generate updated threat scenarios for all matched patterns or select a specific pattern to view detailed information.
        """
    )
    st.markdown("---")
    
    # --- File paths ---
    attack_file_path = "util\\capec.json"
    threat_file_path = ".files\\unified_attack_model.json"

    # Load threat scenarios once to populate the dropdown (using session state)
    if "threat_scenarios" not in st.session_state:
        try:
            st.session_state.threat_scenarios = load_threat_scenarios(threat_file_path)
        except Exception as e:
            st.error(f"Error loading threat scenarios: {e}")
            st.stop()

    # Create two columns for the UI elements
    col1, col2 = st.columns(2)

    with col1:
        scenario_options = {
            f"{i+1}: Asset: {s['asset']} | Threat: {s['threat']} | Vector: {s['vector']}": s
            for i, s in enumerate(st.session_state.threat_scenarios)
        }
        scenario_keys = list(scenario_options.keys())
        scenario_keys.insert(0, "ALL")
        selected_option = st.selectbox("Select a threat scenario or ALL", scenario_keys)
        
        # Put the Check Similarities button below the dropdown in the same column
        check_similarities = st.button("Check Similarities")

    with col2:
        threshold = st.slider(
    "Similarity Threshold", 0.0, 1.0, 0.6, 0.05,
    help="Set the similarity threshold (default: 0.6). If no results are returned, try reducing the threshold. Note: A lower threshold may reduce accuracy and lead to irrelevant or hallucinated scenarios."
    )

    # Update API key/URL assignment based on model provider
    if model_provider == "OpenAI API":
        api_key = openai_api_key
        use_local_llm = False
    elif model_provider == "Local LLM":
        api_key = None
        use_local_llm = True
        lmstudio_url = f"http://127.0.0.1:{lmstudio_port}"
    else:
        st.error("Unsupported model provider for CAPEC analysis")
        st.stop()

    # Initialize session state for similarity results and updated scenarios
    if "matched_df" not in st.session_state:
        st.session_state.matched_df = None
    if "detailed_mapping" not in st.session_state:
        st.session_state.detailed_mapping = {}
    if "included_updated_scenarios" not in st.session_state:
        st.session_state.included_updated_scenarios = []

    # Run similarity check when button is pressed
    if check_similarities:
        with st.spinner("Be patient! Computing similarities takes time..."):
            try:
                attack_patterns = load_attack_patterns(attack_file_path)
                st.session_state.attack_patterns = attack_patterns
            except Exception as e:
                st.error(f"Error loading attack patterns: {e}")
                st.stop()

            results = []
            detailed_mapping = {}

            if selected_option == "ALL":
                for label, scenario in scenario_options.items():
                    threat_text = scenario.get("scenario_text", "")
                    similar_patterns = compute_similarities(threat_text, attack_patterns, threshold)
                    for sim, pat in similar_patterns:
                        raw_data = pat["raw"]
                        key = f"{scenario.get('id', '')}_{pat['id']}"
                        results.append({
                            "Key": key,
                            "Scenario ID": scenario.get("id", ""),
                            "Asset": scenario.get("asset", ""),
                            "Threat": scenario.get("threat", ""),
                            "Vector": scenario.get("vector", ""),
                            "Attack Description": raw_data.get("Description", "N/A"),
                            "Likelihood": raw_data.get("Likelihood_Of_Attack", "N/A"),
                            "Severity": raw_data.get("Typical_Severity", "N/A"),
                            "Similarity Score": f"{sim:.2f}"
                        })
                        detailed_mapping[key] = raw_data
            else:
                selected_scenario = scenario_options[selected_option]
                threat_text = selected_scenario.get("scenario_text", "")
                similar_patterns = compute_similarities(threat_text, attack_patterns, threshold)
                for sim, pat in similar_patterns:
                    raw_data = pat["raw"]
                    key = f"{selected_scenario.get('id', '')}_{pat['id']}"
                    results.append({
                        "Key": key,
                        "Scenario ID": selected_scenario.get("id", ""),
                        "Asset": selected_scenario.get("asset", ""),
                        "Threat": selected_scenario.get("threat", ""),
                        "Vector": selected_scenario.get("vector", ""),
                        "Attack Description": raw_data.get("Description", "N/A"),
                        "Likelihood": raw_data.get("Likelihood_Of_Attack", "N/A"),
                        "Severity": raw_data.get("Typical_Severity", "N/A"),
                        "Similarity Score": f"{sim:.2f}"
                    })
                    detailed_mapping[key] = raw_data

        if results:
            df = pd.DataFrame(results)
            st.session_state.matched_df = df
            st.session_state.detailed_mapping = detailed_mapping
            st.markdown("### Similarity Results")
            st.dataframe(df.drop(columns=["Key"]))
        else:
            st.warning("No similar attack patterns found for the selected scenario(s) with the given threshold.")

    if st.session_state.matched_df is not None and st.session_state.detailed_mapping:
        # Filter out already included scenarios from dropdown
        included_keys = [item.get("key") for item in st.session_state.get("included_updated_scenarios", [])]
        filtered_df = st.session_state.matched_df[~st.session_state.matched_df["Key"].isin(included_keys)]
        
        if not filtered_df.empty:
            # Add "ALL" option to the dropdown
            dropdown_options = ["ALL"] + list(filtered_df["Key"].unique())
            selected_key = st.selectbox(
                "Select a scenario to view details and generate threat scenario", 
                dropdown_options
            )
            
            if selected_key == "ALL":
                st.markdown("#### Generate Updated Threat Scenarios for All Patterns")
                if api_key or use_local_llm:
                    if st.button("Generate All Updated Scenarios", key="gen_all_scenarios"):
                        all_updates = []
                        
                        with st.spinner("Generating updates for all patterns..."):
                            for key in filtered_df["Key"].unique():
                                detail = st.session_state.detailed_mapping[key]
                                scenario_id = filtered_df.loc[filtered_df["Key"] == key, "Scenario ID"].iloc[0]
                                current_scenario = next(s for s in st.session_state.threat_scenarios 
                                                     if s["id"] == scenario_id)
                                
                                threat_text = current_scenario.get("scenario_text", "")
                                attack_details = flatten_field(detail)
                                
                                if use_local_llm:
                                    generated_update = generate_updated_threat_scenario_llmlocal(
                                        threat_text,
                                        attack_details,
                                        current_scenario,
                                        lmstudio_url,
                                        selected_model
                                    )
                                else:
                                    generated_update = generate_updated_threat_scenario(
                                        threat_text,
                                        attack_details,
                                        current_scenario,
                                        api_key
                                    )
                                
                                if "error" not in generated_update:
                                    # Store simplified data
                                    new_scenario = {
                                        "key": key,
                                        "generated_update": {
                                            "updated_threat_scenario": generated_update["updated_threat_scenario"],
                                            "attack_paths": generated_update["attack_paths"],
                                            "mitigation_strategies": generated_update["mitigation_strategies"]
                                        }
                                    }
                                    st.session_state.included_updated_scenarios.append(new_scenario)
                                    all_updates.append((key, generated_update))
                        
                        # Display updates in table
                        if all_updates:
                            table_rows = []
                            table_rows.append("| Scenario ID | Updated Threat Scenario | Attack Paths | Mitigation Strategies |")
                            table_rows.append("|-------------|------------------------|--------------|---------------------|")
                            
                            for key, update in all_updates:
                                scenario = clean_text_for_markdown(update.get("updated_threat_scenario"))
                                paths = clean_text_for_markdown(update.get("attack_paths"))
                                mitigations = clean_text_for_markdown(update.get("mitigation_strategies"))
                                row = f"| {key} | {scenario} | {paths} | {mitigations} |"
                                table_rows.append(row)
                            
                            st.markdown("#### Generated Updates for All Patterns")
                            st.markdown("\n".join(table_rows))
                            
                            save_scenario_data({"scenarios": st.session_state.included_updated_scenarios}, is_temp=True)
                            st.success("All scenarios generated and saved!")

            elif selected_key:
                # Show detailed attack pattern information
                st.markdown("#### Attack Pattern Details")
                detail = st.session_state.detailed_mapping[selected_key]
                with st.expander("**Attack Pattern Description**"):
                    st.write(detail.get("Description", "N/A"))
                if "Execution_Flow" in detail:
                    with st.expander("**Execution Flow**"):
                        exec_flow = detail.get("Execution_Flow", {})
                        if "Attack_Step" in exec_flow:
                            steps = exec_flow["Attack_Step"]
                            if isinstance(steps, list):
                                for step in steps:
                                    st.markdown(f"<span style='color: #2E86C1;'><b>Step {step.get('Step', '')} - {step.get('Phase', '')}:</b></span>", unsafe_allow_html=True)
                                    st.write(step.get("Description", ""))
                            else:
                                st.markdown("<span style='color: #2E86C1;'><b>Execution Flow:</b></span>", unsafe_allow_html=True)
                                st.write(steps.get("Description", ""))
                        else:
                            st.write("N/A")
                if "Consequences" in detail:
                    with st.expander("**Consequences**"):
                        consequences = detail.get("Consequences", {})
                        if isinstance(consequences, dict):
                            for key, value in consequences.items():
                                st.markdown(f"<span style='color: #CB4335;'><b>{key}:</b></span>", unsafe_allow_html=True)
                                st.write(value)
                        elif isinstance(consequences, list):
                            for consequence in consequences:
                                st.markdown(f"<span style='color: #CB4335;'><b>Consequence:</b></span>", unsafe_allow_html=True)
                                st.write(consequence)
                        else:
                            st.write(consequences)

                if api_key or use_local_llm:
                    st.markdown("#### Generate Threat Scenario")
                    # Get scenario details before generation
                    if selected_option != "ALL":
                        # For single scenario selection, use the selected scenario
                        scenario_id = filtered_df.loc[filtered_df["Key"] == selected_key, "Scenario ID"].iloc[0]
                        current_scenario = next(s for s in st.session_state.threat_scenarios 
                                             if s["id"] == scenario_id)
                    else:
                        current_scenario = st.session_state.threat_scenarios[0]
                    
                    if st.button("Generate Scenario", key="gen_scenario"):
                        threat_text = current_scenario.get("scenario_text", "")
                        attack_details = flatten_field(detail)
                        
                        if use_local_llm:
                            generated_update = generate_updated_threat_scenario_llmlocal(
                                threat_text,
                                attack_details,
                                current_scenario,
                                lmstudio_url,
                                selected_model
                            )
                        else:
                            generated_update = generate_updated_threat_scenario(
                                threat_text,
                                attack_details,
                                current_scenario,
                                api_key
                            )
                        
                        # Store only essential data when generating single scenario
                        if "error" not in generated_update:
                            new_scenario = {
                                "key": selected_key,
                                "generated_update": {
                                    "updated_threat_scenario": generated_update["updated_threat_scenario"],
                                    "attack_paths": generated_update["attack_paths"],
                                    "mitigation_strategies": generated_update["mitigation_strategies"]
                                }
                            }
                            if "generated_scenarios" not in st.session_state:
                                st.session_state.generated_scenarios = {}
                            st.session_state.generated_scenarios[selected_key] = new_scenario
                            st.session_state.last_generated = selected_key

                    # Display all generated updates that exist in session state
                    if "generated_scenarios" in st.session_state:
                        for pattern_key, gen_data in st.session_state.generated_scenarios.items():
                            with st.expander(f"Generated Scenario for {pattern_key}", 
                                           expanded=(pattern_key == selected_key)):
                                
                                generated_update = gen_data["generated_update"]
                                scenario = clean_text_for_markdown(generated_update.get("updated_threat_scenario"))
                                paths = clean_text_for_markdown(generated_update.get("attack_paths"))
                                mitigations = clean_text_for_markdown(generated_update.get("mitigation_strategies"))
                                
                                md_table = f"""| Scenario ID | Updated Threat Scenario | Attack Paths | Mitigation Strategies |
                                                |-------------|------------------------|--------------|---------------------|
                                                | {pattern_key} | {scenario} | {paths} | {mitigations} |"""
                                st.markdown(md_table)

                                # Show inclusion checkbox with callback for this pattern
                                include_key = f"include_{pattern_key}"
                                
                                def create_checkbox_callback(key, data):
                                    def callback():
                                        if st.session_state[include_key]:
                                            if "included_updated_scenarios" not in st.session_state:
                                                st.session_state.included_updated_scenarios = []
                                            if key not in [item.get("key") for item in st.session_state.included_updated_scenarios]:
                                                st.session_state.included_updated_scenarios.append(data)
                                                save_scenario_data({"scenarios": st.session_state.included_updated_scenarios}, is_temp=True)
                                        else:
                                            if "included_updated_scenarios" in st.session_state:
                                                st.session_state.included_updated_scenarios = [
                                                    s for s in st.session_state.included_updated_scenarios 
                                                    if s.get("key") != key
                                                ]
                                                save_scenario_data({"scenarios": st.session_state.included_updated_scenarios}, is_temp=True)
                                    return callback

                                st.checkbox(
                                    "Include this scenario in final output",
                                    key=include_key,
                                    value=pattern_key in [item.get("key") for item in st.session_state.get("included_updated_scenarios", [])],
                                    on_change=create_checkbox_callback(pattern_key, gen_data)
                                )

        else:
            st.info("All scenarios from current similarity search have been included. Run a new similarity check or adjust threshold if needed.")

    if st.session_state.get("included_updated_scenarios"):
        final_output = {"updated_threat_scenarios": st.session_state.get("included_updated_scenarios", [])}
        
        # Save final version to file
        if save_scenario_data(final_output, is_temp=False):
            # st.success("The scenario saved successfully!")
            st.info("The scenario saved, generate other scenarios or download the final output.")
            # Offer download option
            json_output = json.dumps(final_output, indent=2)
            st.download_button(
                label="Download",
                data=json_output,
                file_name="capec-based_scenarios.json",
                mime="application/json"
            )
  
# ------------------ Report ------------------- #

with tab7:
    # Create directory for report images if it doesn't exist
    report_images_dir = os.path.join(os.getcwd(), ".files", ".report_images")
    os.makedirs(report_images_dir, exist_ok=True)

    # Get existing screenshots before creating the layout
    existing_screenshots = [f for f in os.listdir(report_images_dir) 
                          if f.lower().endswith(('.png', '.jpg', '.jpeg'))]

    # Initialize current image index if not exists
    if 'current_image_index' not in st.session_state:
        st.session_state.current_image_index = 0

    # Create two columns for the main layout
    col1, col2 = st.columns([1, 1])

    with col1:
        st.text_input("Application name", help="Enter the name of the application.", key="app_name")
        st.text_input("Author", help="Enter the name of the author.", key="author")
        st.text_area("High-level description", help="Enter a high-level description of the application.", key="high_level_description")
        
        # Add attack graph upload section
        st.markdown("#### Upload Attack Graph")
        uploaded_files = st.file_uploader(
            "Upload new screenshots",
            accept_multiple_files=True,
            type=['png', 'jpg', 'jpeg'],
            help="Upload new attack graphs to include in the report"
        )

        # Handle uploaded files
        if uploaded_files:
            for uploaded_file in uploaded_files:
                file_path = os.path.join(report_images_dir, uploaded_file.name)
                try:
                    with open(file_path, "wb") as f:
                        f.write(uploaded_file.getbuffer())
                    st.success(f"Saved: {uploaded_file.name}")
                except Exception as e:
                    st.error(f"Error saving {uploaded_file.name}: {e}")
            
    with col2:
        st.text_input("Application version", help="Enter the version of the application.", key="app_version")
        st.date_input("Date", key="date", help="Enter the date of the report.", format="YYYY/MM/DD")
        font_options = ["Arial", "Times New Roman", "Helvetica", "Verdana"]
        st.selectbox("Font", options=font_options, key="font", help="Select the font for the report")
        st.slider("Font size", 10, 16, 12, 1, key="font_size", help="Select the font size for the report")

        # Display existing screenshots
        display_screenshots(existing_screenshots, report_images_dir)
        

    # Show preview of available data
    if st.checkbox("Preview Report Data"):
        st.write("#### Available Data for Report")
        # Check if CAPEC analysis file exists and risk assessment file exists
        capec_file_path = os.path.join(os.getcwd(), ".files", "capec-based_scenarios.json")
        risk_file_path = os.path.join(os.getcwd(), ".files", "risk_assessment.json")
        has_capec_analysis = os.path.exists(capec_file_path)
        has_risk_assessment = os.path.exists(risk_file_path)
        report_data = {
            'Application Info': bool(st.session_state.get('app_name') and 
                                  st.session_state.get('author') and 
                                  st.session_state.get('app_version')),
            'Attack Model': bool(st.session_state.get('attack_model')),
            'Security Controls': bool(st.session_state.get('security_controls')),
            'Risk Assessment': has_risk_assessment,
            'CAPEC Analysis': has_capec_analysis,
            'Attack Graphs': bool(load_saved_attack_graphs())
        }
        
        # Display data availability status with explanations
        for key, status in report_data.items():
            icon = '✅' if status else '❌'
            st.write(f"{key}: {icon}")
            if not status:
                if key == 'Application Info':
                    st.info("Please fill in the application name, author, and version above.")
                elif key == 'Attack Graphs':
                    st.info("Please upload attack graph screenshots to include them in the report.")
                elif key == 'CAPEC Analysis':
                    st.info("Generate CAPEC analysis in the 'CAPEC Analysis' tab first.")
                elif key == 'Risk Assessment':
                    st.info("Complete the Risk Assessment process in the 'Risk Assessment' tab first.")
                else:
                    st.info(f"Generate {key} in the corresponding tab first.")

    # Update the Generate Report button condition to simpler requirements
    required_data = (
        st.session_state.get("app_name") and 
        st.session_state.get("author")
    )
    
    if st.button("Generate Report", disabled=not required_data):
        with st.spinner("Generating report..."):
            try:
                download_file()
                st.success("Report generated successfully! Check your downloads folder.")
            except Exception as e:
                st.error(f"Error generating report: {e}")
                st.write("Error details:", str(e))
