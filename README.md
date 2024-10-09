# AutoSecGPT

AutoSecGPT is an AI-powered tool designed to help security teams produce better threat models for their automotive applications. Aligned with the ISO/SAE 21434 standard, AutoSecGPT supports security teams by facilitating the entire cybersecurity engineering process—from threat identification to risk assessment. It helps anticipate and prepare for potential attack scenarios by emphasizing the identification and assessment of cybersecurity risks, a key aspect of ISO/SAE 21434. The tool addresses gaps in threat modeling, a critical activity in the automotive software development lifecycle that is often overlooked or poorly executed.

## Features
- **Works with various LLMs**: Leverage OpenAI and other large language models to analyze automotive threat scenarios.
- **Automotive-specific threat identification**: Recognize and assess security threats unique to automotive systems.
- **Generate detailed threat scenarios**: Automatically generate scenarios and descriptions to enhance risk understanding.
- **Visualize attack graphs**: Understand the root causes of threats through detailed attack graphs.
- **Conduct risk assessments**: Perform likelihood and impact assessments to prioritize threats and propose mitigation strategies.
- **TARA support**: Supports Threat Analysis and Risk Assessment (TARA) as defined by ISO/SAE 21434 for the automotive industry.

## Installation

To install and run the project, clone the repository and install the necessary dependencies:

```bash
git clone https://github.com/Majid-Mollaeefar/auto-sec-gpt.git
cd auto-sec-gpt
pip install -r requirements.txt
streamlit run main.py
```

## Usage

After installation, simply run the tool by following the instructions on the web interface. The tool is API-driven and works with multiple LLM providers, including:

- **OpenAI** (API key required for full functionality)
- **MistralAI**
- **Google Gemini**

To get started, you'll need an API key from one of these providers. OpenAI is the most widely supported provider at the moment, with some features being exclusive to OpenAI's API. To request support for additional LLM providers, please submit an issue or open a pull request.


## Example Workflow

1. **Threat Model**  
   In this tab, you can conduct a comprehensive threat modeling exercise for your automotive application. Define assets, evaluate associated threats, and assess their potential consequences. You can document and download your findings in structured formats like JSON and Markdown to improve your system's security posture.

2. **Attack Model**  
   Based on the identified threats, this tab provides a detailed attack model for each asset, investigating scenarios of how attacks might occur in the system. The attack model includes a comprehensive breakdown of each threat, specifying attack vectors and scenarios. Each identified threat outlines attacker objectives, along with possible attack vectors.

3. **Attack Graph**  
   This tab visualizes the attack graph for each asset, presenting the relationships between assets, threats, attack vectors, and scenarios. The graph dynamically displays interconnected nodes, helping to understand the progression from initial threats to potential attack scenarios and corresponding controls. To use this tab:
   - Select an asset from the dropdown list.
   - Click on nodes to explore related threats, attack vectors, and scenarios.
   - In the "Scenario Detail" box, you can add or remove scenarios for further risk assessment.
   - After selecting scenarios for each asset, click 'Selection Completed'. This will generate a downloadable JSON file for use in the Risk Assessment process.

4. **Risk Assessment**  
   In this tab, you can perform a comprehensive risk assessment. You must first complete the **Likelihood Assessment**, followed by the **Impact Assessment**:
   - **Likelihood Assessment**: Determine the likelihood level of each attack scenario based on a set of predefined likelihood factors.
   - **Impact Assessment**: Evaluate the impact level of each attack scenario using predefined impact factors.
   - **Risk Evaluation**: Finally, compute the risk levels based on the combination of likelihood and impact. Click the 'Risk Evaluation' button to generate the risk assessment.

## Demo

For a detailed demonstration of the tool, watch the video below:

- [Demo Video](https://majidml.com/assets/tool/long-demo.mp4)

## Contacts

AutoSecGPT is developed by [Majid Mollaeefar](https://www.linkedin.com/in/majid-mollaeefar/). For any questions, feature requests, or feedback, feel free to contact me directly via LinkedIn or submit an issue on the GitHub repository.
