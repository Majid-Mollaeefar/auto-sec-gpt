import streamlit as st
import os
import json
import numpy as np
import pandas as pd
import time
# Function to load the final impact assessment
def load_impact_assessment():
    base_path = os.getcwd()
    file_path = os.path.join(base_path, ".files\\final_impact_assessment.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return None

def calculate_attack_potential(risk_level):
    if risk_level >= 25:
        return "Beyond High"
    elif risk_level >= 20:
        return "High"
    elif risk_level >= 14:
        return "Moderate"
    elif risk_level >= 10:
        return "Enhanced-Basic"
    else:
        return "Basic"
    
def calculate_average_likelihood(likelihood_factors):
    values = [factor['Value'] for factor in likelihood_factors]
    # Check for exceptions
    elapsed_time_value = likelihood_factors[0]['Value']
    window_of_opportunity_value = likelihood_factors[3]['Value']
    
    if elapsed_time_value == -1 or window_of_opportunity_value == -1:
        return "Not Applicable"
    
    average_likelihood = np.mean(values)
    return average_likelihood

def calculate_average_impact(impact_factors):
    severities = [factor['Severity'] for factor in impact_factors]
    average_impact = np.mean(severities)
    return average_impact

def risk_evaluation():
    st.subheader("Risk Evaluation")
    # Load the final impact assessment data
    impact_data = load_impact_assessment()

    if impact_data is None:
        st.error("No final impact assessment file found. Please complete the Impact Assessment first.")
        return

    scenarios = impact_data["Scenarios"]
    
    # Evaluate risk for each scenario
    for scenario in scenarios:
        likelihood_factors = scenario["Likelihood"]
        impact_factors = scenario["Impact"]

        avg_likelihood = calculate_average_likelihood(likelihood_factors)

        if avg_likelihood == "Not Applicable":
            risk_level = "Not Applicable"
        else:
            avg_impact = calculate_average_impact(impact_factors)
            risk_level = avg_likelihood * avg_impact

        scenario["Risk Level"] = risk_level
    
    # Save the risk assessment results
    risk_assessment_path = os.path.join(os.getcwd(), ".files\\risk_assessment.json")
    with open(risk_assessment_path, "w") as f:
        json.dump({"Scenarios": scenarios}, f, indent=4)
    
    st.success(f"Risk Assessment successfully completed.")

def load_risk_assessment():
    base_path = os.getcwd()
    file_path = os.path.join(base_path, ".files\\risk_assessment.json")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return json.load(f)
    return None

def display_prioritized_risks():
    st.subheader("Prioritized Risk Levels")
    risk_data = load_risk_assessment()
    
    time.sleep (1)
    if risk_data is None:
        st.error("No risk assessment data found. Please perform the Risk Evaluation first.")
        return

    scenarios = risk_data["Scenarios"]
    
    # Prepare data for display
    risk_values = []
    for scenario in scenarios:
        risk_level = scenario["Risk Level"]
        if risk_level == "Not Applicable":
            risk_level = 0  # Treat "Not Applicable" as zero risk
    
        attack_potential = calculate_attack_potential(risk_level)

        risk_values.append({
            "Asset": scenario["asset"],
            "Threat": scenario["threat"],
            "Attack Vector": scenario["vector"],
            "Scenario ID": scenario["scenario_id"],
            "Risk Level": risk_level,
            "Attack Potential": attack_potential
        })

    # Convert to DataFrame and sort by Risk Level
    df = pd.DataFrame(risk_values)
    df = df.sort_values(by="Risk Level", ascending=False)
    # Display the sorted DataFrame
    st.dataframe(df)    
