# util.py

import streamlit as st
import time
levels = {
    "Elapsed Time": ["less than 1 day", "less than 1 week", "less than 1 month", "less than 3 months", "less than 6 months", "more than 6 months", "not practical"],
    "Expertise": ["Layman", "Proficient", "Expert", "Multiple experts"],
    "Knowledge of system": ["Public", "Restricted", "Sensitive", "Critical"],
    "Window of Opportunity": ["Unnecessary/unlimited", "Easy", "Moderate", "Difficult", "None"],
    "Equipment": ["Standard", "Specialised", "Bespoke", "Multiple bespoke"]
}

comments = {
    "Elapsed Time": [
        "no comment", "no comment", "no comment", "no comment", "no comment", "no comment", "The attack path is not exploitable within a timescale that would be useful to an attacker."
    ],
    "Expertise": [
        "Unknowledgeable compared to experts or proficient persons, with no particular expertise",
        "Knowledgeable in being familiar with the security behaviour of the product or system type.",
        "Familiar with the underlying algorithms, protocols, hardware, structures, security behaviour, principles and concepts of security employed, techniques and tools for the definition of new attacks, cryptography, classical attacks for the product type, attack methods, etc.",
        "Different fields of expertise are required at an Expert level for distinct steps of an attack."
    ],
    "Knowledge of system": [
        "e.g. as gained from the Internet",
        "e.g. knowledge that is controlled within the developer organisation and shared with other organisations under a non-disclosure agreement",
        "e.g. knowledge that is shared between discreet teams within the developer organisation, access to which is constrained only to team members",
        "e.g. knowledge that is known by only a few individuals, access to which is very tightly controlled on a strict need-to-know basis and individual undertaking"
    ],
    "Window of Opportunity": [
        "The attack does not need any kind of opportunity to be realized because there is no risk of being detected during access to the target of the attack and it is no problem to access the required number of targets for the attack.",
        "Access is required for less than 1 day and number of targets required performing the attack less than 10.",
        "Access is required for less than 1 month and number of targets required to perform the attack less than 100.",
        "Access is required for more than 1 month or number of targets required to perform the attack more than 100.",
        "The opportunity window is not sufficient to perform the attack (the access to the target is too short to perform the attack, or a sufficient number of targets is not accessible to the attacker)."
    ],
    "Equipment": [
        "Readily available to the attacker",
        "Not readily available to the attacker, but acquirable without undue effort. This could include purchase of moderate amounts of equipment or development of more extensive attack scripts or programs.",
        "Not readily available to the public because equipment may need to be specially produced, is so specialised that its distribution is restricted, or is very expensive.",
        "Different types of bespoke equipment are required for distinct steps of an attack."
    ]
}

values = {
    "Elapsed Time": [0, 1, 4, 7, 10, 19, -1],
    "Expertise": [0, 3, 6, 8],
    "Knowledge of system": [0, 3, 7, 11],
    "Window of Opportunity": [0, 1, 4, 10, -1],
    "Equipment": [0, 4, 6, 9]
}

def reset_risk_assessment_state():
    """Resets session state variables for risk assessment."""
    for key in ["risk_assessment_tab", "selected_scenario", "selected_levels",
                "submitted_scenarios", "available_scenarios", "update_scenario"]:
        if key in st.session_state:
            del st.session_state[key]
