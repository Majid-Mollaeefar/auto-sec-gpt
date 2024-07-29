import streamlit as st
import pandas as pd
import json
import os
import time
from util import levels, comments, values, reset_risk_assessment_state

def extract_and_merge_scenarios(files):
    merged_data = {"assets": []}

    for file in files:
        try:
            data = json.load(file)
            if "threats" in data:
                asset_name = data.get("name", "Unknown Asset")
                for threat in data["threats"]:
                    threat["asset_name"] = asset_name
                merged_data["assets"].append(data)
            else:
                st.error(f"The file {file.name} does not contain 'threats' key.")
                return None, None
        except json.JSONDecodeError:
            st.error(f"The file {file.name} is not a valid JSON.")
            return None, None

    scenarios = []
    scenario_mapping = {}

    for asset in merged_data['assets']:
        asset_name = asset['name']
        for threat in asset['threats']:
            threat_name = threat['name']
            for vector in threat['vectors']:
                vector_name = vector['vector_name']
                for idx, scenario in enumerate(vector['scenarios']):
                    scenario_desc = scenario['scenario_description']
                    full_scenario_id = f"{asset_name} - {threat_name} - {vector_name} - scenario_{idx + 1}"
                    simple_scenario_id = f"scenario_{idx + 1}"
                    scenarios.append(full_scenario_id)
                    scenario_mapping[full_scenario_id] = {
                        "asset": asset_name,
                        "threat": threat_name,
                        "vector": vector_name,
                        "scenario_id": simple_scenario_id,
                        "scenario_desc": scenario_desc
                    }
    return scenarios, scenario_mapping

# Function to integrate likelihood assessment into the selected scenario
def integrate_likelihood(scenario_details, selected_levels, comments, values):
    likelihood = [
        {
            "Factor": factor,
            "Level": selected_levels[factor],
            "Value": values[factor][levels[factor].index(selected_levels[factor])],
            "Comment": comments[factor][levels[factor].index(selected_levels[factor])]
        }
        for factor in levels
    ]
    scenario_details['Likelihood'] = likelihood
    return scenario_details

def risk_assessment_customized(key):
    st.subheader("Upload JSON Files")
    uploaded_files = st.file_uploader("Choose JSON files", accept_multiple_files=True, type="json", key=key)
    
    if uploaded_files:
        scenarios, scenario_mapping = extract_and_merge_scenarios(uploaded_files)
        
        if scenarios:
            # Initialize session state for selected scenario and likelihood
            if "selected_scenario" not in st.session_state:
                st.session_state.selected_scenario = scenarios[0]
            if "selected_levels" not in st.session_state:
                st.session_state.selected_levels = {factor: levels[factor][0] for factor in levels}
            if "submitted_scenarios" not in st.session_state:
                st.session_state.submitted_scenarios = []
            if "available_scenarios" not in st.session_state:
                st.session_state.available_scenarios = scenarios.copy()
            if "update_scenario" not in st.session_state:
                st.session_state.update_scenario = False

            st.title("Threat Evaluation Form")

            # Select scenario
            if st.session_state.update_scenario:
                if st.session_state.available_scenarios:
                    st.session_state.selected_scenario = st.session_state.available_scenarios[0]
                else:
                    st.session_state.selected_scenario = None
                st.session_state.update_scenario = False
                st.experimental_rerun()

            st.subheader("Select Attack Scenario")
            if st.session_state.available_scenarios:
                selected_scenario = st.selectbox("", st.session_state.available_scenarios, key="selected_scenario")
                scenario_details = scenario_mapping[selected_scenario]

                # Display scenario details in a styled box
                st.markdown(
                    f"""
                    <div style="border: 2px solid #f56b6b; padding: 10px; border-radius: 10px; background-color: #273750;">
                        <h4>Scenario Details</h4>
                        <p><strong>Asset:</strong> {scenario_details['asset']}</p>
                        <p><strong>Threat:</strong> {scenario_details['threat']}</p>
                        <p><strong>Attack Vector:</strong> {scenario_details['vector']}</p>
                        <p><strong>Scenario Description:</strong> {scenario_details['scenario_desc']}</p>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                # Initialize DataFrame for likelihood assessment
                data = {
                    "Likelihood Factors": list(levels.keys()),
                    "Levels": [st.session_state.selected_levels[factor] for factor in levels],
                    "Comments": [comments[factor][levels[factor].index(st.session_state.selected_levels[factor])] for factor in levels],
                    "Values": [values[factor][levels[factor].index(st.session_state.selected_levels[factor])] for factor in levels]
                }
                df = pd.DataFrame(data)

                # Display the table with dropdowns
                st.subheader("Select Likelihood Levels")
                for index, row in df.iterrows():
                    factor = row["Likelihood Factors"]
                    selected_level = st.selectbox(
                        f"Select level for {factor}",
                        levels[factor],
                        index=levels[factor].index(row["Levels"]),
                        key=f"{factor.replace(' ', '_').replace('(', '').replace(')', '')}"
                    )
                    df.at[index, "Levels"] = selected_level
                    df.at[index, "Comments"] = comments[factor][levels[factor].index(selected_level)]
                    df.at[index, "Values"] = values[factor][levels[factor].index(selected_level)]
                    st.session_state.selected_levels[factor] = selected_level

                # Display the updated DataFrame without the row index
                st.write("### Updated Likelihood Assessment Table")
                st.dataframe(df.style.hide(axis='index'))

            else:
                st.write("No scenarios available")

            # Create buttons in the same row
            col1, col2, col3 = st.columns(3)

            with col1:
                submit_button = st.button("Submit Evaluation", help="By clicking on this button you can submit your evaluation of the attack scenario", key="submit", disabled=not st.session_state.available_scenarios)
            with col2:
                remove_button = st.button("Remove Evaluation", help="By clicking on this button you can remove your last evaluation", key="remove", disabled=not st.session_state.submitted_scenarios)
            with col3:
                finalize_button = st.button("Finalize Evaluation", help="By clicking on this button you finalize your likelihood evaluation for the selected attack scenarios", key="finalize")

            # Display the number of submitted scenarios
            st.subheader("Submitted Scenarios")
            st.write(f"Number of submitted scenarios: {len(st.session_state.submitted_scenarios)}")

            # Handle the form submission for likelihood evaluation
            if submit_button:
                evaluated_scenario = integrate_likelihood(scenario_details, st.session_state.selected_levels, comments, values)
                st.session_state.submitted_scenarios.append(evaluated_scenario)
                st.session_state.available_scenarios.remove(selected_scenario)
                time.sleep(0.1)
                st.experimental_rerun()  # Refresh the page to update scenario selection

            # Handle removal of a submitted scenario
            if remove_button:
                if st.session_state.submitted_scenarios:
                    last_submitted = st.session_state.submitted_scenarios.pop()
                    scenario_key = f"{last_submitted['asset']} - {last_submitted['threat']} - {last_submitted['vector']} - {last_submitted['scenario_id']}"
                    st.session_state.available_scenarios.append(scenario_key)
                    st.session_state.available_scenarios = sorted(st.session_state.available_scenarios)
                    st.session_state.update_scenario = True
                    time.sleep(0.1)
                    st.experimental_rerun()  # Refresh the page to update scenario selection

            # Handle final likelihood assessment
            if finalize_button:
                if st.session_state.submitted_scenarios:
                    base_path = os.getcwd()
                    json_path = os.path.join(base_path)
                    final_result = {"Scenarios": st.session_state.submitted_scenarios}
                    file_path = os.path.join(json_path, ".files\\final_likelihood_assessment.json")
                    with open(file_path, "w") as f:
                        json.dump(final_result, f, indent=4)
                    st.write(f"Final Likelihood Assessment submitted and JSON file saved to {file_path}")
                    reset_risk_assessment_state()  # Reset session state
                    time.sleep(0.1)
                    st.experimental_rerun()
                else:
                    st.error("No scenarios submitted. Please submit at least one scenario before finalizing.")
