#likelihood_assessment_full.py

import streamlit as st
import pandas as pd
import json
import os
import time
from util import levels, comments, values, reset_likelihood_assessment_state

def likelihood_assessment_full():
    base_path = os.getcwd()
    file_path = os.path.join(base_path, ".files\\unified_attack_model.json")
    with open(file_path, 'r') as file:
        attack_model = json.load(file)

    scenarios = []
    scenario_mapping = {}

    for asset in attack_model['assets']:
        asset_name = asset['name']
        for threat in asset['threats']:
            threat_name = threat['name']
            for vector in threat['vectors']:
                vector_name = vector['vector_name']
                for scenario in vector['scenarios']:
                    scenario_id = scenario['scenario_id']
                    scenario_desc = scenario['scenario_description']
                    scenario_key = f"{asset_name} - {threat_name} - {vector_name} - {scenario_id}"
                    scenarios.append(scenario_key)
                    scenario_mapping[scenario_key] = {
                        "asset": asset_name,
                        "threat": threat_name,
                        "vector": vector_name,
                        "scenario_id": scenario_id,
                        "scenario_desc": scenario_desc
                    }

    if scenarios:
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

    st.title("Threat Likelihood Evaluation Form")

    if st.session_state.update_scenario:
        if st.session_state.available_scenarios:
            st.session_state.selected_scenario = st.session_state.available_scenarios[0]
        else:
            st.session_state.selected_scenario = None
        st.session_state.update_scenario = False
        st.rerun()

    st.subheader("Select Attack Scenario")
    if st.session_state.available_scenarios:
        selected_scenario = st.selectbox("", st.session_state.available_scenarios, key="selected_scenario")
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

    col1, col2, col3 = st.columns(3)

    with col1:
        submit_button = st.button("Submit Evaluation", help="Submit your evaluation", key="submit", disabled=not st.session_state.available_scenarios)
    with col2:
        remove_button = st.button("Remove Evaluation", help="Remove last evaluation", key="remove", disabled=not st.session_state.submitted_scenarios)
    with col3:
        finalize_button = st.button("Finalize Evaluation", help="Finalize evaluation", key="finalize")

    st.subheader("Submitted Scenarios")
    st.write(f"Number of submitted scenarios: {len(st.session_state.submitted_scenarios)}")

    if submit_button:
        evaluated_scenario = integrate_likelihood(scenario_details, st.session_state.selected_levels, comments, values)
        st.session_state.submitted_scenarios.append(evaluated_scenario)
        st.session_state.available_scenarios.remove(selected_scenario)
        time.sleep(0.1)
        st.rerun()

    if remove_button:
        if st.session_state.submitted_scenarios:
            last_submitted = st.session_state.submitted_scenarios.pop()
            scenario_key = f"{last_submitted['asset']} - {last_submitted['threat']} - {last_submitted['vector']} - {last_submitted['scenario_id']}"
            st.session_state.available_scenarios.append(scenario_key)
            st.session_state.available_scenarios = sorted(st.session_state.available_scenarios)
            st.session_state.update_scenario = True
            time.sleep(0.1)
            st.rerun()

    if finalize_button:
        if st.session_state.submitted_scenarios:
            base_path = os.getcwd()
            json_path = os.path.join(base_path)
            final_result = {"Scenarios": st.session_state.submitted_scenarios}
            file_path = os.path.join(json_path, ".files\\final_likelihood_assessment.json")
            with open(file_path, "w") as f:
                json.dump(final_result, f, indent=4)
            st.success(f"Likelihood Assessment successfully submitted.")
            reset_likelihood_assessment_state()  # Reset session state
            st.session_state.likelihood_assessment_complete = True
            time.sleep(0.1)
            # st.query_params = {"tab": "Risk Assessment"}
            # st.rerun()  # Refresh the page
        else:
            st.error("No scenarios submitted. Please submit at least one scenario before finalizing.")