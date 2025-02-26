import pdfkit
import os
import streamlit as st
import base64
from datetime import datetime
import markdown
import streamlit.components.v1 as components
import json

def format_threat_model_for_report(threat_model):
    """Convert threat model to a more readable HTML format"""
    html = "<div class='threat-section'>"
    if isinstance(threat_model, list):
        for asset in threat_model:
            html += f"""
                <div class='asset-block'>
                    <h3>Asset: {asset.get('name', 'N/A')}</h3>
                    <p><strong>Description:</strong> {asset.get('description', 'N/A')}</p>
                    <div class='threats'>
            """
            for threat in asset.get('threats', []):
                html += f"""
                    <div class='threat-block'>
                        <h4>Threat: {threat.get('name', 'N/A')}</h4>
                        <p><strong>Objectives:</strong></p>
                        <ul>
                            {''.join(f'<li>{obj}</li>' for obj in threat.get('objectives', []))}
                        </ul>
                    </div>
                """
            html += "</div></div>"
    html += "</div>"
    return html

def format_attack_model_for_report(attack_model):
    """Convert attack model to a more readable HTML format"""
    # Similar structure to threat model but with attack-specific formatting
    # ...implementation...

def format_controls_for_report(controls):
    """Convert controls to a more readable HTML format"""
    html = "<div class='controls-section'>"
    if isinstance(controls, dict):
        for asset, asset_controls in controls.items():
            html += f"""
                <div class='asset-controls'>
                    <h3>Asset: {asset}</h3>
                    <table class='controls-table'>
                        <tr>
                            <th>Control Type</th>
                            <th>Description</th>
                            <th>Priority</th>
                        </tr>
            """
            for control in asset_controls:
                html += f"""
                    <tr>
                        <td>{control.get('type', 'N/A')}</td>
                        <td>{control.get('description', 'N/A')}</td>
                        <td>{control.get('priority', 'N/A')}</td>
                    </tr>
                """
            html += "</table></div>"
    html += "</div>"
    return html

class ReportGenerator:
    def __init__(self):
        self.css = """
            body { 
                font-family: var(--font-family);
                font-size: var(--font-size);
                margin: 40px;
            }
            table { 
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }
            table, th, td {
                border: 1px solid #ddd;
                padding: 8px;
            }
            th {
                background-color: #f5f5f5;
                font-weight: bold;
            }
            .cover { text-align: center; margin-bottom: 50px; }
            .cover h1 { color: #f56b6b; font-size: 28px; }
            .section { margin-bottom: 30px; }
            .section h2 { 
                color: #273750; 
                border-bottom: 2px solid #f56b6b; 
                padding-bottom: 5px; 
            }
            .threat-block {
                margin: 15px 0;
                padding: 15px;
                background: #f8f9fa;
                border-radius: 5px;
                border-left: 3px solid #f56b6b;
            }
            .attack-graph {
                text-align: center;
                margin: 20px 0;
            }
            .attack-graph img {
                max-width: 100%;
                border: 1px solid #ddd;
                padding: 10px;
            }
            .risk-matrix {
                width: 100%;
                margin: 20px 0;
            }
            .risk-level {
                font-weight: bold;
                padding: 5px;
                border-radius: 3px;
            }
            .risk-high { background-color: #ffebee; color: #c62828; }
            .risk-medium { background-color: #fff3e0; color: #ef6c00; }
            .risk-low { background-color: #e8f5e9; color: #2e7d32; }
        """

    def generate_markdown(self, data):
        """Generate markdown content for the report"""
        md = f"""# Security Assessment Report

| | |
|---|---|
| **Application Name** | {data.get('app_name', 'N/A')} |
| **Version** | {data.get('version', 'N/A')} |
| **Author** | {data.get('author', 'N/A')} |
| **Date** | {data.get('date', datetime.now().strftime('%Y-%m-%d'))} |

## Executive Summary
{data.get('description', '')}

## Attack Model Analysis
"""
        # Add attack model section
        if data.get('attack_model'):
            md += f"\n{data['attack_model']}\n\n"
        
        # Add attack graphs section if available
        if data.get('attack_graphs'):
            md += "\n## Attack Graphs\n"
            for graph in data['attack_graphs']:
                md += f"\n### {graph['name']}\n"
                md += f"![{graph['name']}](data:image/png;base64,{graph['data']})\n"

        # Add security controls section
        if data.get('security_controls'):
            md += "\n## Security Controls\n"
            md += f"{data['security_controls']}\n"

        return md

    def convert_to_html(self, markdown_content, font_family='Arial', font_size='14px'):
        """Convert markdown to HTML with styling"""
        html = markdown.markdown(markdown_content, extensions=['tables'])
        
        styled_html = f"""
        <html>
        <head>
            <style>
                {self.css}
                :root {{
                    --font-family: {font_family};
                    --font-size: {font_size};
                }}
            </style>
        </head>
        <body>
            {html}
        </body>
        </html>
        """
        return styled_html

    def get_cover_page(self, app_name, version, author, date, description):
        return f"""
        <div class="cover">
            <h1>Security Threat Model Report</h1>
            <h2>{app_name}</h2>
            <p><strong>Version:</strong> {version}</p>
            <p><strong>Prepared by:</strong> {author}</p>
            <p><strong>Date:</strong> {date}</p>
            <div class="header-box">
                <h3>Executive Summary</h3>
                <p>{description}</p>
            </div>
        </div>
        """

    def get_system_overview(self, threat_model):
        # Extract system information from threat model
        assets = set()
        if isinstance(threat_model, list):
            for item in threat_model:
                if isinstance(item, dict) and 'name' in item:
                    assets.add(item['name'])
        
        return f"""
        <div class="section">
            <h2>System Overview</h2>
            <div class="subsection">
                <h3>Key Assets</h3>
                <ul>
                    {''.join(f'<li>{asset}</li>' for asset in assets)}
                </ul>
            </div>
        </div>
        """

    def get_threat_assessment(self, threat_model):
        return f"""
        <div class="section">
            <h2>Threat Assessment</h2>
            {format_threat_model_for_report(threat_model)}
        </div>
        """

    def get_attack_analysis(self, attack_model, attack_graphs):
        html = f"""
        <div class="section">
            <h2>Attack Analysis</h2>
            {format_attack_model_for_report(attack_model)}
        """
        
        if attack_graphs:
            html += """
            <div class="subsection">
                <h3>Attack Graphs</h3>
            """
            for graph in attack_graphs:
                asset_name = graph['name']
                image_data = graph['data']
                html += f"""
                <div class="attack-graph">
                    <h4>{asset_name}</h4>
                    <img src="data:image/png;base64,{image_data}" />
                </div>
                """
            html += "</div>"
        
        html += "</div>"
        return html

    def get_security_controls(self, controls):
        return f"""
        <div class="section">
            <h2>Security Controls</h2>
            {format_controls_for_report(controls)}
        </div>
        """

    def get_risk_assessment(self, risk_evaluation, risk_matrix):
        return f"""
        <div class="section">
            <h2>Risk Assessment</h2>
            <div class="subsection">
                <h3>Risk Evaluation</h3>
                <pre>{risk_evaluation}</pre>
            </div>
            <div class="subsection">
                <h3>Risk Matrix</h3>
                <div class="risk-matrix">
                    {risk_matrix}
                </div>
            </div>
        </div>
        """

    def generate_report(self, data):
        """Generate the final report"""
        html_content = self.convert_to_html(
            self.generate_markdown(data),
            font_family=st.session_state.get('font', 'Arial'),
            font_size=f"{st.session_state.get('font_size', 14)}px"
        )

        output_path = os.path.join(os.getcwd(), '.files', 'threat_model_report.pdf')
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        options = {
            'page-size': 'A4',
            'margin-top': '20mm',
            'margin-right': '20mm',
            'margin-bottom': '20mm',
            'margin-left': '20mm',
            'encoding': "UTF-8",
            'enable-local-file-access': True
        }
        
        try:
            pdfkit.from_string(html_content, output_path, options=options)
            return output_path
        except Exception as e:
            st.error(f"Error generating PDF: {e}")
            st.write("HTML content for debugging:", html_content)
            raise e

def load_saved_attack_graphs():
    """Load all saved attack graphs from uploaded files"""
    graphs = []
    report_images_dir = os.path.join(os.getcwd(), ".files", ".report_images")
    
    if os.path.exists(report_images_dir):
        try:
            # Create a copy of the images in a temporary directory
            temp_dir = os.path.join(os.getcwd(), ".files", ".report_images_temp")
            os.makedirs(temp_dir, exist_ok=True)
            
            # Copy all images to temp directory
            for filename in os.listdir(report_images_dir):
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    src_path = os.path.join(report_images_dir, filename)
                    dst_path = os.path.join(temp_dir, filename)
                    with open(src_path, 'rb') as src, open(dst_path, 'wb') as dst:
                        dst.write(src.read())
            
            # Load images from the temporary directory
            for filename in os.listdir(temp_dir):
                if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
                    try:
                        with open(os.path.join(temp_dir, filename), 'rb') as f:
                            asset_name = os.path.splitext(filename)[0]
                            graphs.append({
                                'name': asset_name,
                                'data': base64.b64encode(f.read()).decode()
                            })
                    except Exception as e:
                        st.error(f"Error loading attack graph {filename}: {e}")
            
        except Exception as e:
            st.error(f"Error handling attack graphs: {e}")
        finally:
            # Keep the original images intact
            if os.path.exists(temp_dir):
                import shutil
                shutil.rmtree(temp_dir)
    
    return graphs

def download_file():
    """Generate and trigger the report download"""
    try:
        # Generate markdown content with all sections
        markdown_content = generate_report_content()
        
        # Generate PDF with the content
        pdf_content = generate_pdf(markdown_content)
        
        # Encode PDF for download
        b64 = base64.b64encode(pdf_content).decode()
        
        # Create download trigger with dynamic filename
        filename = f"security_assessment_report_{datetime.now().strftime('%Y%m%d')}.pdf"
        
        download_html = f"""
        <html>
        <head>
        <script>
        document.addEventListener('DOMContentLoaded', function() {{
            var link = document.createElement('a');
            link.href = 'data:application/pdf;base64,{b64}';
            link.download = '{filename}';
            link.click();
        }});
        </script>
        </head>
        </html>
        """
        
        components.html(download_html, height=0)
        
    except Exception as e:
        st.error(f"Error generating report: {str(e)}")
        raise Exception(f"Error generating report: {str(e)}")

def generate_risk_assessment_table():
    """Generate a markdown table from risk assessment JSON data"""
    try:
        # Read the risk assessment JSON file
        risk_file = os.path.join(os.getcwd(), ".files", "risk_assessment.json")
        if not os.path.exists(risk_file):
            return None
            
        with open(risk_file, 'r') as f:
            risk_data = json.load(f)
        
        # Create table headers
        table = "| Scenario ID | Asset | Threat | Attack Vector | Risk Level |\n"
        table += "|------------|--------|---------|---------------|------------|\n"
        
        # Add each scenario to the table
        for scenario in risk_data.get("Scenarios", []):
            table += (f"| {scenario.get('scenario_id', 'N/A')} | "
                     f"{scenario.get('asset', 'N/A')} | "
                     f"{scenario.get('threat', 'N/A')} | "
                     f"{scenario.get('vector', 'N/A')} | "
                     f"{scenario.get('Risk Level', 'N/A')} |\n")
        
        return table
    except Exception as e:
        st.error(f"Error generating risk assessment table: {e}")
        return None

def generate_report_content():
    """Generate the markdown content for the report"""
    # Get application details from session state
    app_name = st.session_state.get('app_name', 'N/A')
    app_version = st.session_state.get('app_version', 'N/A')
    author = st.session_state.get('author', 'N/A')
    date = st.session_state.get('date', datetime.now()).strftime('%Y-%m-%d')
    description = st.session_state.get('high_level_description', '')

    text = "# Automotive Security Assessment Report\n\n"
    
    # Report Details section with correct data
    text += "## Report Details\n\n"
    text += "| | |\n"
    text += "|---|---|\n"
    text += f"| **Application Name** | {app_name} |\n"
    text += f"| **Application Version** | {app_version} |\n"
    text += f"| **Report Author** | {author} |\n"
    text += f"| **Date** | {date} |\n"
    
    if description:
        text += f"| **Description** | {description} |\n"
    
    text += "\n"  # Add extra newline for spacing

    # Attack Model section
    if "attack_model" in st.session_state:
        text += "## Attack Model Analysis\n\n"
        text += "The attack model analysis identifies potential attack vectors and scenarios for each asset. "
        text += "It provides a detailed breakdown of how attackers might target the system, including their objectives and methods.\n\n"
        text += "### Attack Model Details\n\n"
        text += st.session_state["attack_model"] + "\n\n"
    
    # Security Controls section
    if "security_controls" in st.session_state:
        text += "## Security Controls\n\n"
        text += "This section outlines the recommended security controls based on ISO/SAE 21434 and NIST SP 800-53 standards. "
        text += "The controls are categorized by type (Preventive, Detective, and Corrective) and prioritized for implementation. "
        text += "Each control is designed to mitigate specific identified threats.\n\n"
        text += "### Security Control Measures\n\n"
        text += st.session_state["security_controls"] + "\n\n"
    
    # Risk Assessment section
    risk_table = generate_risk_assessment_table()
    if risk_table:
        text += "## Risk Assessment\n\n"
        text += "The following table presents the risk assessment results for identified threat scenarios. "
        text += "Each scenario is evaluated based on its potential impact and likelihood, resulting in an overall risk level.\n\n"
        text += "### Risk Assessment Results\n\n"
        text += risk_table + "\n\n"
        text += "_Risk Levels: Higher values indicate greater risk severity._\n\n"

    
    # CAPEC Analysis section
    capec_file = os.path.join(os.getcwd(), ".files", "capec-based_scenarios.json")
    if os.path.exists(capec_file):
        try:
            with open(capec_file, 'r') as f:
                capec_data = json.load(f)
            
            text += "## CAPEC Analysis\n\n"
            text += "This section presents the results of analyzing the identified threat scenarios against the CAPEC "
            text += "(Common Attack Pattern Enumeration and Classification) database. This analysis provides additional "
            text += "insights into potential attack patterns and corresponding mitigation strategies.\n\n"
            
            if "updated_threat_scenarios" in capec_data:
                for scenario in capec_data["updated_threat_scenarios"]:
                    if "generated_update" in scenario:
                        update = scenario["generated_update"]
                        text += f"### Scenario {scenario['key']}\n\n"
                        
                        text += "#### Updated Threat Scenario\n"
                        text += f"{update.get('updated_threat_scenario', 'N/A')}\n\n"
                        
                        text += "#### Attack Paths\n"
                        text += f"{update.get('attack_paths', 'N/A')}\n\n"
                        
                        text += "#### Mitigation Strategies\n"
                        text += f"{update.get('mitigation_strategies', 'N/A')}\n\n"
                        
                        text += "---\n\n"
        except Exception as e:
            st.error(f"Error loading CAPEC analysis: {e}")
    
    # Attack Graphs section (always at the end)
    graphs = load_saved_attack_graphs()
    if graphs:
        text += "## Attack Graphs\n\n"
        text += "These visualizations illustrate the attack paths and relationships between assets, threats, "
        text += "attack vectors, and scenarios. The graphs help understand potential attack progression "
        text += "and the interconnections between different security elements.\n\n"
        for graph in graphs:
            text += f"### Attack Graph: {graph['name']}\n\n"
            text += f"![{graph['name']}](data:image/png;base64,{graph['data']})\n\n"
    
    return text

def generate_pdf(markdown_content):
    """Convert markdown to PDF with enhanced styling"""
    html = markdown.markdown(markdown_content, extensions=["markdown.extensions.tables"])
    
    # Enhanced CSS styling
    html_with_style = f"""
    <html>
    <head>
    <style>
        body {{
            font-family: {st.session_state.get("font", "Arial")};
            font-size: {st.session_state.get("font_size", 12)}px;
            line-height: 1.6;
            color: #333;
        }}
        h1 {{
            color: #273750;
            text-align: center;
            font-size: 24px;
            margin-bottom: 30px;
        }}
        h2 {{
            color: #f56b6b;
            border-bottom: 2px solid #f56b6b;
            padding-bottom: 5px;
            margin-top: 25px;
        }}
        h3 {{
            color: #273750;
            margin-top: 20px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background-color: #fff;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #f5f5f5;
            font-weight: bold;
        }}
        img {{
            max-width: 100%;
            height: auto;
            margin: 20px 0;
            border: 1px solid #ddd;
            padding: 5px;
        }}
        p {{
            margin-bottom: 15px;
            text-align: justify;
        }}
    </style>
    </head>
    <body>
    {html}
    </body>
    </html>
    """
    
    # PDF options
    options = {
        'page-size': 'A4',
        'margin-top': '20mm',
        'margin-right': '20mm',
        'margin-bottom': '20mm',
        'margin-left': '20mm',
        'encoding': "UTF-8",
        'enable-local-file-access': True
    }
    
    return pdfkit.from_string(html_with_style, False, options=options)



def display_screenshots(existing_screenshots, report_images_dir):
    """
    Display existing screenshots with navigation controls.
    
    Args:
        existing_screenshots (list): List of screenshot filenames
        report_images_dir (str): Directory path containing the screenshots
    """
    if existing_screenshots:
        st.markdown("#### Currently Saved Attack Graphs")
        
        # Initialize current_image_index if not exists
        if 'current_image_index' not in st.session_state:
            st.session_state.current_image_index = 0

        # Main image display
        current_img_name = existing_screenshots[st.session_state.current_image_index]
        img_path = os.path.join(report_images_dir, current_img_name)
        
        # Display image with center alignment using CSS
        st.markdown(
            """
            <style>
                .centered-image {
                    display: flex;
                    justify-content: center;
                    margin: 0 auto;
                    max-width: 600px;
                }
            </style>
            """,
            unsafe_allow_html=True
        )
        
        st.markdown(
            f'<div class="centered-image">',
            unsafe_allow_html=True
        )
        st.image(
            img_path, 
            caption=f"Image {st.session_state.current_image_index + 1}/{len(existing_screenshots)}", 
            use_column_width=False,
            width=600
        )
        st.markdown('</div>', unsafe_allow_html=True)
        
        st.markdown(
            f"<div style='text-align: center; font-size: 0.8em;'>{current_img_name}</div>", 
            unsafe_allow_html=True
        )

        # Navigation buttons in a single row
        nav_cols = st.columns(3)
        with nav_cols[0]:
            if st.button("⬅️", use_container_width=True):
                st.session_state.current_image_index = (st.session_state.current_image_index - 1) % len(existing_screenshots)
                # st.rerun()
        with nav_cols[1]:
            if st.button("Clear All", help="Clear all screenshots", use_container_width=True):
                try:
                    for file in existing_screenshots:
                        os.remove(os.path.join(report_images_dir, file))
                    st.session_state.current_image_index = 0
                    st.success("Cleared!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")
        with nav_cols[2]:
            if st.button("➡️", use_container_width=True):
                st.session_state.current_image_index = (st.session_state.current_image_index + 1) % len(existing_screenshots)
                # st.rerun()