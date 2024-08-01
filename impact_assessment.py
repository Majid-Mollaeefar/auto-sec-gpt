import streamlit as st
import pandas as pd
import os
import json
import time
from util import impact_levels, reset_impact_assessment_state

# Function to check if the final likelihood assessment file exists
def likelihood_assessment_file_exists():
    base_path = os.getcwd()
    file_path = os.path.join(base_path, ".files\\final_likelihood_assessment.json")
    return os.path.exists(file_path)

# Function to load the final likelihood assessment
def load_likelihood_assessment():
    base_path = os.getcwd()
    file_path = os.path.join(base_path, ".files\\final_likelihood_assessment.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return None

def impact_assessment():
    st.title("Impact Assessment")

    # Load the final likelihood assessment
    likelihood_data = load_likelihood_assessment()

    if likelihood_data is None:
        st.write("No data available from Likelihood Assessment. Please complete the Likelihood Assessment first.")
        return

    scenarios = likelihood_data["Scenarios"]
    scenario_mapping = {}

    for scenario in scenarios:
        scenario_id = scenario['scenario_id']
        scenario_desc = scenario['scenario_desc']
        scenario_key = f"{scenario['asset']} - {scenario['threat']} - {scenario['vector']} - {scenario_id}"
        scenario_mapping[scenario_key] = {
            "asset": scenario['asset'],
            "threat": scenario['threat'],
            "vector": scenario['vector'],
            "scenario_id": scenario_id,
            "scenario_desc": scenario_desc,
            "Likelihood": scenario['Likelihood']
        }

    if scenarios:
        # Initialize session state for impact assessment if not already done
        if "impact_selected_scenario" not in st.session_state:
            st.session_state.impact_selected_scenario = list(scenario_mapping.keys())[0]
        if "impact_selected_levels" not in st.session_state:
            st.session_state.impact_selected_levels = {factor: impact_levels[factor][0] for factor in impact_levels}
        if "impact_submitted_scenarios" not in st.session_state:
            st.session_state.impact_submitted_scenarios = []
        if "impact_available_scenarios" not in st.session_state:
            st.session_state.impact_available_scenarios = list(scenario_mapping.keys())
        if "impact_update_scenario" not in st.session_state:
            st.session_state.impact_update_scenario = False

    # Select scenario
    if st.session_state.impact_update_scenario:
        if st.session_state.impact_available_scenarios:
            st.session_state.impact_selected_scenario = st.session_state.impact_available_scenarios[0]
        else:
            st.session_state.impact_selected_scenario = None
        st.session_state.impact_update_scenario = False
        st.rerun()

    st.subheader("Select Attack Scenario")
    if st.session_state.impact_available_scenarios:
        selected_scenario = st.selectbox("", st.session_state.impact_available_scenarios, key="impact_selected_scenario")
        scenario_details = scenario_mapping[selected_scenario]

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

        # Initialize data for impact assessment
        data = {
            "Impact Factors": ["Safety", "Privacy", "Financial", "Operational"],
            "Description": [
                impact_levels["Safety"][0],
                impact_levels["Privacy"][0],
                impact_levels["Financial"][0],
                impact_levels["Operational"][0]
            ],
            "Severity Level": [0, 0, 0, 0]
        }

        df = pd.DataFrame(data)

        session_key = f"impact_assessment_{scenario_details['scenario_id']}"
        if session_key not in st.session_state:
            st.session_state[session_key] = df

        st.subheader("Select Impact Levels")
        for index, row in st.session_state[session_key].iterrows():
            factor = row["Impact Factors"]
            selected_value = st.selectbox(
                f"Select {factor}",
                impact_levels[factor],
                index=impact_levels[factor].index(row["Description"]),
                key=f"impact_{factor.replace(' ', '_').replace('(', '').replace(')', '')}_{scenario_details['scenario_id']}"
            )
            st.session_state[session_key].at[index, "Severity Level"] = impact_levels[factor].index(selected_value)
            st.session_state[session_key].at[index, "Description"] = selected_value

        st.write("### Updated Impact Assessment Table")
        st.dataframe(st.session_state[session_key].style.hide(axis='index'))
    else:
        st.write("No scenarios available")

    # Define the integrate_impact function here
    def integrate_impact(scenario_details, impact_df):
        impact = [
            {
                "Factor": row["Impact Factors"],
                "Level": row["Description"],
                "Severity": row["Severity Level"]
            }
            for _, row in impact_df.iterrows()
        ]
        scenario_details['Impact'] = impact
        return scenario_details

    col1, col2, col3 = st.columns(3)

    with col1:
        submit_button = st.button("Submit Impact", help="Submit your impact assessment", key="impact_submit", disabled=not st.session_state.impact_available_scenarios)
    with col2:
        remove_button = st.button("Remove Impact", help="Remove last impact assessment", key="impact_remove", disabled=not st.session_state.impact_submitted_scenarios)
    with col3:
        finalize_button = st.button("Finalize Impact", help="Finalize impact assessment", key="impact_finalize", disabled=not st.session_state.impact_submitted_scenarios)

    # Display the number of submitted scenarios
    st.subheader("Submitted Scenarios")
    st.write(f"Number of submitted scenarios: {len(st.session_state.impact_submitted_scenarios)}")

    if submit_button:
        evaluated_scenario = integrate_impact(scenario_details, st.session_state[session_key])
        st.session_state.impact_submitted_scenarios.append(evaluated_scenario)
        st.session_state.impact_available_scenarios.remove(selected_scenario)
        time.sleep(0.1)
        st.rerun()

    if remove_button:
        if st.session_state.impact_submitted_scenarios:
            last_submitted = st.session_state.impact_submitted_scenarios.pop()
            scenario_key = f"{last_submitted['asset']} - {last_submitted['threat']} - {last_submitted['vector']} - {last_submitted['scenario_id']}"
            st.session_state.impact_available_scenarios.append(scenario_key)
            st.session_state.impact_available_scenarios = sorted(st.session_state.impact_available_scenarios)
            st.session_state.impact_update_scenario = True
            # st.warning(f"Impact Assessment for {last_submitted['scenario_id']} removed.")
            time.sleep(0.1)
            st.rerun()

    if finalize_button:
        if st.session_state.impact_submitted_scenarios:
            base_path = os.getcwd()
            json_path = os.path.join(base_path)
            final_result = {"Scenarios": st.session_state.impact_submitted_scenarios}
            file_path = os.path.join(json_path, ".files\\final_impact_assessment.json")
            with open(file_path, "w") as f:
                json.dump(final_result, f, indent=4)
            st.success(f"Impact Assessment submitted and JSON file saved to {file_path}")
            reset_impact_assessment_state()  # Reset session state
            st.session_state.impact_assessment_complete = True
            time.sleep(0.1)
            st.query_params = {"tab": "Risk Evaluation"}  # Move to the Risk Evaluation tab
            st.rerun()
        else:
            st.error("No scenarios submitted. Please submit at least one scenario before finalizing.")