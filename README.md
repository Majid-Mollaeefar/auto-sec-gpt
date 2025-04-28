# AutoSecGPT

AutoSecGPT is an AI-powered tool designed to help security teams produce better threat models for their automotive applications. Aligned with the ISO/SAE 21434 standard, AutoSecGPT supports security teams by facilitating the entire cybersecurity engineering process—from threat identification to risk assessment. It helps anticipate and prepare for potential attack scenarios by emphasizing the identification and assessment of cybersecurity risks, a key aspect of ISO/SAE 21434. The tool addresses gaps in threat modeling, a critical activity in the automotive software development lifecycle that is often overlooked or poorly executed.

## Features
- **Works with various LLMs**: Leverage OpenAI and other large language models to analyze automotive threat scenarios.
- **Works with LM Studio**: The newly added functionality to use local models by using LM Studio.
- **Automotive-specific threat identification**: Recognize and assess security threats unique to automotive systems.
- **Generate detailed threat scenarios**: Automatically generate scenarios and descriptions to enhance risk understanding.
- **Identify security controls**: List relevant security controls for mitigating identified threats based on NIST SP 800-53.
- **Visualize attack graphs**: Understand the root causes of threats through detailed attack graphs.
- **Conduct risk assessments**: Perform likelihood and impact assessments to prioritize threats and propose mitigation strategies.
- **TARA support**: Supports Threat Analysis and Risk Assessment (TARA) as outlined by ISO/SAE 21434 for the automotive industry.
- **CAPEC Analysis**: Leverage MITRE CAPEC (Common Attack Pattern Enumeration and Classification) to enhance threat scenario generation by using an NLP technique to conduct a similarity check with CAPEC. 
- **Comprehensive Report Generation**: Generate detailed PDF reports including:
  - Threat model analysis
  - Security controls recommendations
  - Risk assessment results
  - Attack graphs visualization
  - CAPEC-based generated threat scenarios

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

To get started, you'll need an API key from one of these providers. OpenAI is the most widely supported provider at the moment, with some features being exclusive to OpenAI's API. To request support for additional LLM providers, please submit an issue or open a pull request.

> **Note:** The data in the `/.files` directory contains example outputs. Please clean this directory before starting your own threat modeling process to ensure accurate results.

## Local LLM Integration with LM Studio

If you prefer using local LLMs rather than cloud-based services, LM Studio is a powerful solution that allows you to run and manage LLMs on your own hardware. 
We recommend using **qwen2.5-7b-instruct** as a reliable and efficient choice for local deployments with AutoSecGPT.

### To Use LM Studio with AutoSecGPT:

1. **Install LM Studio:**  
   Download and install LM Studio from the official website.

2. **Enable Developer Mode and Load Models:**  
   Switch to Developer mode within LM Studio and load the available models. 

3. **Fetch and Select a Local Model:**  
   AutoSecGPT will connect to your LM Studio instance (using the specified port, default is **7860**) to retrieve the list of installed models.  
   - If no models are found or LM Studio is not running, an error message will be displayed.
   - If models are available, select the model you wish to use (e.g., **qwen2.5-7b-instruct**) from the provided list.

4. **Proceed with Your Application:**  
   Once the model is selected, continue by providing the application details and generating threat lists, attack models, and visualizing asset-based attack graphs for your application.


## Example Workflow

1. **Threat Model**  
   In this tab, you can conduct a comprehensive threat modeling exercise for your automotive application. Define assets, evaluate associated threats, and assess their potential consequences. You can document and download your findings in structured formats like JSON and Markdown to improve your system's security posture.

2. **Attack Model**  
   Based on the identified threats, this tab provides a detailed attack model for each asset, investigating scenarios of how attacks might occur in the system. The attack model includes a comprehensive breakdown of each threat, specifying attack vectors and scenarios. Each identified threat outlines attacker objectives, along with possible attack vectors.

3. **Security Controls**  
   It identifies appropriate security controls for each identified threat based on ISO/SAE 21434 and NIST SP 800-53 standards. 
   The controls are categorized by type (Preventive, Detective, and Corrective) and prioritized for implementation. Each control includes a detailed description and implementation priority to help guide the security hardening process. 

4. **Attack Graph**  
   This tab visualizes the attack graph for each asset, presenting the relationships between assets, threats, attack vectors, and scenarios. The graph dynamically displays interconnected nodes, helping to understand the progression from initial threats to potential attack scenarios and corresponding controls. To use this tab:
   - Select an asset from the dropdown list.
   - Click on nodes to explore related threats, attack vectors, and scenarios.
   - In the "Scenario Detail" box, you can add or remove scenarios for further risk assessment.
   - After selecting scenarios for each asset, click 'Selection Completed'. This will generate a downloadable JSON file for use in the Risk Assessment process.

5. **Risk Assessment**  
   In this tab, you can perform a comprehensive risk assessment. You must first complete the **Likelihood Assessment**, followed by the **Impact Assessment**:
   - **Likelihood Assessment**: Determine the likelihood level of each attack scenario based on a set of predefined likelihood factors.
   - **Impact Assessment**: Evaluate the impact level of each attack scenario using predefined impact factors.
   - **Risk Evaluation**: Finally, compute the risk levels based on the combination of likelihood and impact. Click the 'Risk Evaluation' button to generate the risk assessment.

6. **CAPEC Analysis**  
   This tab enhances your threat scenarios by mapping them to MITRE's Common Attack Pattern Enumeration and Classification (CAPEC):
   - Select specific scenarios from your threat model for CAPEC analysis
   - The system uses NLP to match your scenarios with relevant CAPEC patterns
   - Review matched patterns and their detailed descriptions
   - Generate updated threat scenarios incorporating CAPEC insights
   - View execution flow and attack steps for each pattern
   - Export the enhanced scenarios for inclusion in the final report

7. **Report**  
   Generate comprehensive security assessment reports in this tab:
   - Enter basic application information (name, version, author)
   - Upload and manage attack graph screenshots using the built-in viewer
   - Preview available report components before generation
   - Customize report appearance (font, size)
   - Generate a PDF report including:
     - Application details
     - Attack model analysis
     - Security controls recommendations
     - Risk assessment results
     - CAPEC-based threat scenarios
     - Attack graph visualizations
   - Download the final report for documentation and sharing


## Demo

For a detailed demonstration of the tool, watch the video below:

- [Demo Video](https://majidml.com/assets/tool/long-demo.mp4) (version 1.0.0)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt)
file for details.

## Support

If you find AutoSecGPT is helpful and would like to support the project: 

<a href="https://buymeacoffee.com/majidml" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/default-orange.png" alt="Buy Me A Coffee" style="width:120px;"></a> 

## Contacts

AutoSecGPT is developed by [Majid Mollaeefar](https://www.linkedin.com/in/majid-mollaeefar/). For any questions, feature requests, or feedback, feel free to contact me directly via LinkedIn or submit an issue on the GitHub repository.
