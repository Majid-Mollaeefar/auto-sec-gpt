# AutoSecGPT

AutoSecGPT is an AI-powered tool designed to help teams produce better threat models for their automotive applications. Aligned with the ISO/SAE 21434 standard, AutoSecGPT supports security teams by facilitating the entire cybersecurity engineering process—from threat identification to risk assessment. It helps anticipate and prepare for potential attack scenarios by emphasizing the identification and assessment of cybersecurity risks, a key aspect of ISO/SAE 21434. The tool addresses gaps in threat modeling, a critical activity in the automotive software development lifecycle that is often overlooked or poorly executed.

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

## Contacts

AutoSecGPT is developed by [Majid Mollaeefar](https://www.linkedin.com/in/majid-mollaeefar/). For any questions, feature requests, or feedback, feel free to contact me directly via LinkedIn or submit an issue on the GitHub repository.
