# main.py
import os
import streamlit as st
import streamlit.components.v1 as components
import json
from sidebar import configure_sidebar, render_header
# from attack_vector import (
#     create_attack_scenario_vector_prompt,
#     json_to_markdown_attack_model,
# )
from mitigations import (
    create_mitigations_prompt,
    get_mitigations,
    get_mitigations_google,
)
from test_cases import create_test_cases_prompt, get_test_cases, get_test_cases_google
from threat_model import (
    create_threat_model_prompt,
    get_threat_model,
    get_threat_model_google,
    json_to_markdown,
    save_json_to_file,
)
from attack_model import create_attack_model_prompt, json_to_markdown_model, create_unified_threat_model
from attack_graph import create_attack_graph, display_attackgraph_html_files
import likelihood_assessment_customized as customized
import likelihood_assessment_full as full
# from impact_assessment import impact_assessment, load_likelihood_assessment, likelihood_assessment_file_exists
import impact_assessment
# from impact_assessment import likelihood_assessment_file_exists
from risk_computation import risk_evaluation, display_prioritized_risks, load_impact_assessment
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

st.sidebar.image("logo.png")

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
        ["OpenAI API", "Google AI API"],
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
            ["gpt-4o-mini","gpt-4o", "gpt-4-turbo", "gpt-4"],
            key="selected_model",
            help="OpenAI have moved to continuous model upgrades so `gpt-4`, `gpt-4-turbo`, `gpt-4o` point to the latest available version of each model.",
        )

    if model_provider == "Google AI API":
        st.markdown(
            """
            1. Enter your [Google AI API key](https://makersuite.google.com/app/apikey) and chosen model below 🔑
            2. Provide details of the application that you would like to model together with additional determined information  📝
            3. Generate a threat list, model attacks, generate and visualize asset-based attack graphs for your application 🚀
            """
        )
        # Add OpenAI API key input field to the sidebar
        google_api_key = st.text_input(
            "Enter your Google AI API key:",
            type="password",
            help="You can generate a Google AI API key in the [Google AI Studio](https://makersuite.google.com/app/apikey).",
        )

        # Add model selection input field to the sidebar
        google_model = st.selectbox(
            "Select the model you would like to use:",
            ["gemini-1.5-pro-latest"],
            key="selected_model",
        )

    st.markdown("""---""")

# Add "About" section to the sidebar
render_header(1)
with st.sidebar:
    st.markdown(
        "Welcome to AutoSecGPT, an AI-powered tool designed to help teams produce better threat models for their applications."
    )
    st.markdown(
        "The ISO/SAE 21434 Road Vehicles—Cybersecurity Engineering standard defines the responsibilities for various groups during different stages of automotive product development. The standard requires a commitment from executive management to product development with a focus on cybersecurity engineering"            
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
    # st.markdown(
    #     "> A new electric car model, features advanced autonomous driving capabilities and an integrated infotainment system. The vehicle connects to various external networks, such as GPS, mobile apps, and charging stations."
    # )

    # st.markdown("""---""")

# ------------------ Main App UI ------------------ #
# Define a function to set the tab state
# def set_tab_state(tab_name):
#     st.session_state.tab = tab_name



tab1, tab2, tab3, tab4 = st.tabs(["Threat Model", "Attack Model", "Attack Graph", "Risk Assessment"])

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
                    if model_provider == "Google AI API":
                        model_output = get_threat_model_google(
                            google_api_key, google_model, threat_model_prompt
                        )
                    elif model_provider == "OpenAI API":
                        model_output = get_threat_model(
                            openai_api_key, selected_model, threat_model_prompt
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
        This tab provides an attack model based on identified threats for each asset and investigates scenarios of how the attacks might happen in the system. The structure of the attack model includes a detailed breakdown of each threat, specifying the attack vectors and scenarios. Each identified threat lists the attacker objectives, followed by various attack vectors.
        """
    )
    st.markdown("""---""")

    if "attack_model_generated" not in st.session_state:
        st.session_state.attack_model_generated = False

    attack_model_submit_button = st.button(label="Generate Attack Model")
    if attack_model_submit_button or st.session_state.attack_model_generated:
        base_path = os.getcwd()
        input_file_name = os.path.join(base_path, ".files\\threats.json")
        api_key = openai_api_key  
        output_file_name = os.path.join(base_path, ".files\\attack_model.json")
        model_name = selected_model  

        if not os.path.exists(output_file_name):
            with st.spinner("Analyzing potential attacks..."):
                max_retries = 5
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        create_attack_model_prompt(
                            api_key, model_name, input_file_name, output_file_name
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
        unified_output_file_name= os.path.join(base_path, ".files\\unified_attack_model.json")
        create_unified_threat_model(input_file_name, output_file_name, unified_output_file_name)
        # Convert the threat model JSON to Markdown
        markdown_output_attack_model = json_to_markdown_model(output_file_name)
        # Display the attack model in Markdown
        st.markdown(markdown_output_attack_model, unsafe_allow_html=True)

# ------------------ Attack Graph ------------------- #
with tab3:
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
            st.error("Unified attack model JSON file does not exist. Please generate the attack model first in the 'Attack Model' tab.")
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

with tab4:
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
        First step of our risk assessment is to detemine the likelihood level of each attack scenario, based on defined a set of likelihood factors.
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
        Second step is to detemine the impact level of each attack scenario, based on defined a set of impact factors.
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
                risk_evaluation()
                display_prioritized_risks()

        # st.markdown("---")
        # if st.button("Show Prioritized Risks"):
        #     display_prioritized_risks()







# # Initialize session state for the tabs and assessments
# if "likelihood_assessment_complete" not in st.session_state:
#     st.session_state.likelihood_assessment_complete = False
# if "impact_assessment_ready" not in st.session_state:
#     st.session_state.impact_assessment_ready = False
# if "impact_assessment_complete" not in st.session_state:
#     st.session_state.impact_assessment_complete = False


# with tab4:
#     st.markdown(
#         """
#         This tab performs a risk assessment. You must first complete the likelihood assessment, and then proceed to the impact assessment.
#         """
#     )

#     st.markdown("---")

#     sub_tabs = st.tabs(["Likelihood Assessment", "Impact Assessment", "Risk Evaluation"])

#    # Likelihood Assessment Tab
#     with sub_tabs[0]:
#         st.markdown("### Likelihood Assessment")
#         likelihood_assessment_option = st.radio(
#             "Select Likelihood Assessment Option:",
#             ["Customized Scenario Selection", "Full Scenario"],
#             key="likelihood_assessment_radio"
#         )

#         if likelihood_assessment_option == "Customized Scenario Selection":
#             customized.likelihood_assessment_customized(key="customized")
#         elif likelihood_assessment_option == "Full Scenario":
#             full.likelihood_assessment_full()

#         if st.session_state.likelihood_assessment_complete:
#             st.success("Likelihood Assessment is complete. You can now proceed to Impact Assessment.")

#     # Impact Assessment Tab
#     with sub_tabs[1]:
#         st.markdown("### Impact Assessment")
#         if st.session_state.likelihood_assessment_complete:
#             st.session_state.impact_assessment_ready = impact_assessment.likelihood_assessment_file_exists()
#             if st.session_state.impact_assessment_ready:
#                 impact_assessment.impact_assessment()
#             else:
#                 st.write("No Likelihood Assessment data found. Complete the Likelihood Assessment first.")
#         else:
#             st.write("Complete the Likelihood Assessment first.")

#     # Risk Evaluation Tab
#     with sub_tabs[2]:
#         st.markdown("### Risk Evaluation")
#         if st.session_state.impact_assessment_complete:
#             st.write("You can now perform the Risk Evaluation based on the completed assessments.")
#             # Risk Evaluation code goes here
#         else:
#             st.write("Complete the Likelihood and Impact Assessments first.")




# # ------------------ Risk Assessment old------------------- #
# with tab4:
#     st.markdown(
#         """
#         This tab performs a risk assessment. Choose one of the options below to proceed.
#         """
#     )

#     st.markdown("---")
    
#     if "likelihood_assessment_tab" not in st.session_state:
#         st.session_state.likelihood_assessment_tab = False

#     # Add a key to the radio button
#     likelihood_assessment_option = st.radio("Select Risk Assessment Option:", ["Customized Scenario Selection", "Full Scenario"], key="likelihood_assessment_radio")  

#     if likelihood_assessment_option == "Customized Scenario Selection":
#         customized.likelihood_assessment_customized(key="customized")
#         st.session_state.likelihood_assessment_tab = True
#     elif likelihood_assessment_option == "Full Scenario":
#         full.likelihood_assessment_full()
#         st.session_state.likelihood_assessment_tab = True
    
#     st.session_state.likelihood_assessment_tab = False

# if st.session_state.likelihood_assessment_tab:
#     st.session_state.query_params = {"tab": "Risk Assessment", "#": "risk-assessment"}




# ------------------ Mitigations Generation ------------------ #

# with tab3:
#     st.markdown("""
# Use this tab to generate potential mitigations for the threats identified in the threat model. Mitigations are security controls or
# countermeasures that can help reduce the likelihood or impact of a security threat. The generated mitigations can be used to enhance
# the security posture of the application and protect against potential attacks.
# """)
#     st.markdown("""---""")

#     # Create a submit button for Mitigations
#     mitigations_submit_button = st.button(label="Suggest Mitigations")

#     # If the Suggest Mitigations button is clicked and the user has identified threats
#     if mitigations_submit_button:
#         # Check if threat_model data exists
#         if 'threat_model' in st.session_state and st.session_state['threat_model']:
#             # Convert the threat_model data into a Markdown list
#             threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
#             # Generate the prompt using the create_mitigations_prompt function
#             mitigations_prompt = create_mitigations_prompt(threats_markdown)

#             # Show a spinner while suggesting mitigations
#             with st.spinner("Suggesting mitigations..."):
#                 max_retries = 3
#                 retry_count = 0
#                 while retry_count < max_retries:
#                     try:
#                         # Call the relevant get_mitigations function with the generated prompt
#                         if model_provider == "Google AI API":
#                             mitigations_markdown = get_mitigations_google(google_api_key, google_model, mitigations_prompt)
#                         elif model_provider == "OpenAI API":
#                             mitigations_markdown = get_mitigations(openai_api_key, selected_model, mitigations_prompt)

#                         # Display the suggested mitigations in Markdown
#                         st.markdown(mitigations_markdown)
#                         break  # Exit the loop if successful
#                     except Exception as e:
#                         retry_count += 1
#                         if retry_count == max_retries:
#                             st.error(f"Error suggesting mitigations after {max_retries} attempts: {e}")
#                             mitigations_markdown = ""
#                         else:
#                             st.warning(f"Error suggesting mitigations. Retrying attempt {retry_count+1}/{max_retries}...")

#             st.markdown("")

#             # Add a button to allow the user to download the mitigations as a Markdown file
#             st.download_button(
#                 label="Download Mitigations",
#                 data=mitigations_markdown,
#                 file_name="mitigations.md",
#                 mime="text/markdown",
#             )
#         else:
#             st.error("Please generate a threat model first before suggesting mitigations.")


# ------------------ Test Cases Generation ------------------ #

# with tab5:
#     st.markdown("""
# Test cases are used to validate the security of an application and ensure that potential vulnerabilities are identified and
# addressed. This tab allows you to generate test cases using Gherkin syntax. Gherkin provides a structured way to describe application
# behaviours in plain text, using a simple syntax of Given-When-Then statements. This helps in creating clear and executable test
# scenarios.
# """)
#     st.markdown("""---""")

#     # Create a submit button for Test Cases
#     test_cases_submit_button = st.button(label="Generate Test Cases")

#     # If the Generate Test Cases button is clicked and the user has identified threats
#     if test_cases_submit_button:
#         # Check if threat_model data exists
#         if 'threat_model' in st.session_state and st.session_state['threat_model']:
#             # Convert the threat_model data into a Markdown list
#             threats_markdown = json_to_markdown(st.session_state['threat_model'], [])
#             # Generate the prompt using the create_test_cases_prompt function
#             test_cases_prompt = create_test_cases_prompt(threats_markdown)

#             # Show a spinner while generating test cases
#             with st.spinner("Generating test cases..."):
#                 max_retries = 3
#                 retry_count = 0
#                 while retry_count < max_retries:
#                     try:
#                         # Call to the relevant get_test_cases function with the generated prompt
#                         if model_provider == "Google AI API":
#                             test_cases_markdown = get_test_cases_google(google_api_key, google_model, test_cases_prompt)
#                         elif model_provider == "OpenAI API":
#                             test_cases_markdown = get_test_cases(openai_api_key, selected_model, test_cases_prompt)


#                         # Display the suggested mitigations in Markdown
#                         st.markdown(test_cases_markdown)
#                         break  # Exit the loop if successful
#                     except Exception as e:
#                         retry_count += 1
#                         if retry_count == max_retries:
#                             st.error(f"Error generating test cases after {max_retries} attempts: {e}")
#                             test_cases_markdown = ""
#                         else:
#                             st.warning(f"Error generating test cases. Retrying attempt {retry_count+1}/{max_retries}...")

#             st.markdown("")

#             # Add a button to allow the user to download the test cases as a Markdown file
#             st.download_button(
#                 label="Download Test Cases",
#                 data=test_cases_markdown,
#                 file_name="test_cases.md",
#                 mime="text/markdown",
#             )
#         else:
#             st.error("Please generate a threat model first before requesting test cases.")