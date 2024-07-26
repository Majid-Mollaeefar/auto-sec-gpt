import json
import os
from streamlit.components.v1 import html
import streamlit as st
from pyvis.network import Network
from streamlit.web import allow_cross_origin

allow_cross_origin()
def create_attack_graph(asset_data, output_dir):
    asset_name = asset_data["name"]
    net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
    net.add_node(asset_name, label=asset_name, color="#0000ff", shape="box")  # Blue box for the asset

    # Dictionary to store unique vectors and scenarios
    unique_nodes = {}

    def get_unique_node_id(node_type, node_name):
        if (node_type, node_name) in unique_nodes:
            return unique_nodes[(node_type, node_name)]
        else:
            unique_id = f"{node_type}_{len(unique_nodes) + 1}"
            unique_nodes[(node_type, node_name)] = unique_id
            return unique_id

    def add_threat_nodes(threat_data):
        threat_name = threat_data["name"]
        objectives_text = "\n- ".join(threat_data["objectives"])
        net.add_node(
            threat_name,
            label=threat_name,
            title=f"Attacker Objectives:\n- {objectives_text}",
            color="#ff0000",
            shape="diamond",
            hidden=True,
        )   # Red diamond
        net.add_edge(
            asset_name, threat_name, title="Threat", color="#ffff00", hidden=True
        )  # Yellow edge for threats

        # Counter for attack vectors
        vector_counter = 1

        for vector in threat_data["vectors"]:
            vector_name = vector["vector_name"]
            vector_id = get_unique_node_id("vector", vector_name)
            net.add_node(vector_id, label=vector_name, color="#ff8080", hidden=True)
            net.add_edge(
                threat_name,
                vector_id,
                label=f"Attack Vector {vector_counter}",  # Label on edge
                color='red',  # Set arrow color to white
                font_color='white', # Set text color to white
                arrows="to",     # Make the arrow point from Threat to vector
                hidden=True,
            )

            # Counter for scenarios
            scenario_counter = 1

            for scenario in vector["scenarios"]:
                scenario_id = get_unique_node_id(
                    "scenario", scenario["scenario_description"]
                )  # Get unique ID
                net.add_node(
                    scenario_id,
                    label=f"Scenario {scenario_counter}",
                    title=scenario["scenario_description"],
                    color="#ffa500",
                    shape="ellipse",
                    hidden=True,
                    data={"asset": asset_name, "threat": threat_name, "vector": vector_name, "scenario_desc": scenario["scenario_description"]}
                )
                net.add_edge(
                    vector_id,
                    scenario_id,
                    title="Leads to",
                    color="#ffa500",
                    hidden=True,
                )
                scenario_counter += 1

            vector_counter += 1

        for control in threat_data["controls"]:
            net.add_node(control, label=control, color="#00ff00", shape="box", hidden=True)  # Green square
            net.add_edge(threat_name, control, title="Control", hidden=True)

    for threat in asset_data["threats"]:
        add_threat_nodes(threat)

    output_path = f"{output_dir}/{asset_name}.html"
    net.save_graph(output_path)

    legend_html = """
    <div id="legend-container" style="position: absolute; bottom: 10px; left: 10px; z-index: 10; background-color: #444; color: white; padding: 10px; border: 2px dashed gray;">
        <h4>Legend</h4>
        <p><span style="color: #0000ff;">&#x25A0;</span> Asset</p>
        <p><span style="color: #ff0000;">&#x25C6;</span> Threat</p>
        <p><span style="color: #ff8080;">&#x25CF;</span> Attack Vector</p>
        <p><span style="color: #ffa500;">&#x2B2C;</span> Scenario</p>
        <p><span style="color: #00ff00;">&#x25A0;</span> Control</p>
    </div>
    <div id="scenario-details" style="position: absolute; bottom: 10px; left: 55%; transform: translateX(-50%); z-index: 10; background-color: #444; color: white; padding: 10px; border: 2px dashed gray; width: 60%; font-size: 12px; display: none;">
        <h4>Scenario Details</h4>
        <p id="scenario-asset"><strong>Asset:</strong> N/A</p>
        <p id="scenario-threat"><strong>Threat:</strong> N/A</p>
        <p id="scenario-vector"><strong>Attack Vector:</strong> N/A</p>
        <p id="scenario-desc"><strong>Scenario Description:</strong> N/A</p>
        <button id="add-scenario-button" onclick="addScenario()" style="background-color: #28a745; color: white; border: none; padding: 5px 10px; cursor: pointer;">+</button>
        <button id="remove-scenario-button" onclick="removeScenario()" style="background-color: #dc3545; color: white; border: none; padding: 5px 10px; cursor: pointer;">-</button>
        <button id="selection-completed-button" onclick="saveSelection()" style="background-color: #17a2b8; color: white; border: none; padding: 5px 10px; cursor: pointer; margin-left: 10px;">Selection Completed</button>
    </div>
    """

    toast_html = """
    <div id="toast-container" style="position: fixed; bottom: 60px; left: 250px; z-index: 100;">
        <div id="toast-message" class="toast hide" role="alert" aria-live="assertive" aria-atomic="true">
            <div class="toast-body"></div>
        </div>
    </div>
    """

    toast_css = """
    <style>
    .toast {
        position: fixed;
        bottom: 0;
        left: 0;
        padding: 0.5rem 1rem;
        margin: 1rem;
        background-color: rgba(0, 0, 0, 0.6);
        color: white;
        border-radius: 0.25rem;
        max-width: 100%;
        z-index: 100;
        opacity: 0;
        transition: opacity 0.05s ease-in-out;
    }

    .toast.show {
        opacity: 1;
    }
    </style>
    """
    legend_html = f"{toast_css}{legend_html}{toast_html}"

    interaction_script = f"""
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script type="text/javascript">
    var lastClickedNode = null;
    var asset_name = '{asset_name}';
    var selected_scenarios = [];
    console.log("Interaction script loaded");

    network.on("dragEnd", function (params) {{
        var nodeId = params.nodes[0];
        if (nodeId) {{
            console.log("Node dragged and fixed:", nodeId);
            network.body.data.nodes.update({{id: nodeId, fixed: {{x: true, y: true}}}});
        }}
    }});

    network.on("click", function (params) {{
        var nodeId = params.nodes[0];
        if (nodeId) {{
            console.log("Node clicked:", nodeId);
            lastClickedNode = nodeId;
            var connectedEdges = network.getConnectedEdges(nodeId);

            connectedEdges.forEach(function (edgeId) {{
                console.log("Connected edge shown:", edgeId);
                network.body.data.edges.update({{id: edgeId, hidden: false}});

                var connectedNodeId = network.getConnectedNodes(edgeId);
                for (var i = 0; i < connectedNodeId.length; i++){{
                    if(connectedNodeId[i] != nodeId){{
                        console.log("Connected node shown:", connectedNodeId[i]);
                        network.body.data.nodes.update({{id: connectedNodeId[i], hidden: false}});
                    }}
                }}
            }});

            var nodeData = network.body.data.nodes.get(nodeId);
            console.log("Node data:", nodeData);
            if (nodeData.data) {{
                const scenarioDetails = nodeData.data;
                document.getElementById("scenario-asset").innerText = "Asset: " + scenarioDetails.asset;
                document.getElementById("scenario-threat").innerText = "Threat: " + scenarioDetails.threat;
                document.getElementById("scenario-vector").innerText = "Attack Vector: " + scenarioDetails.vector;
                document.getElementById("scenario-desc").innerText = "Scenario Description: " + scenarioDetails.scenario_desc;
                document.getElementById("scenario-details").style.display = "block";
            }}
        }}
    }});

    function zoomIn() {{
        var scale = network.getScale();
        console.log("Zooming in, scale:", scale);
        network.moveTo({{ scale: scale + 0.1 }});
    }}

    function zoomOut() {{
        var scale = network.getScale();
        console.log("Zooming out, scale:", scale);
        network.moveTo({{ scale: scale - 0.1 }});
    }}

    function maximize() {{
        var container = document.getElementById('graph-legend-container');
        if (container.requestFullscreen) {{
            console.log("Maximizing");
            container.requestFullscreen();
        }} else if (container.mozRequestFullScreen) {{
            console.log("Maximizing with mozRequestFullScreen");
            container.mozRequestFullScreen();
        }} else if (container.webkitRequestFullscreen) {{
            console.log("Maximizing with webkitRequestFullscreen");
            container.webkitRequestFullscreen();
        }} else if (container.msRequestFullscreen) {{
            console.log("Maximizing with msRequestFullscreen");
            container.msRequestFullscreen();
        }}
    }}

    function saveAsPNG() {{
        var buttons = document.getElementById('buttons-container');
        buttons.style.display = 'none';
        html2canvas(document.getElementById('graph-legend-container')).then(canvas => {{
            var link = document.createElement('a');
            link.href = canvas.toDataURL();
            link.download = '{asset_name}-Attack-graph.png';
            console.log("Saving as PNG");
            link.click();
            buttons.style.display = 'block';
        }});
    }}

    // Add toast message
    function showToast(message) {{
        var toast = document.getElementById("toast-message");
        var toastBody = toast.querySelector(".toast-body");
        toastBody.textContent = message;
        toast.classList.remove("hide");
        toast.classList.add("show");
        setTimeout(function () {{
            toast.classList.remove("show");
            toast.classList.add("hide");
        }}, 500);
    }}

    function addScenario() {{
        if (lastClickedNode && selected_scenarios.indexOf(lastClickedNode) === -1) {{
            selected_scenarios.push(lastClickedNode);
            console.log("Scenario added:", lastClickedNode);
            showToast("Scenario added.");
        }}
    }}

    function removeScenario() {{
        if (lastClickedNode && selected_scenarios.indexOf(lastClickedNode) !== -1) {{
            selected_scenarios.splice(selected_scenarios.indexOf(lastClickedNode), 1);
            console.log("Scenario removed:", lastClickedNode);
            showToast("Scenario removed.");
        }}
    }}

    function saveSelection() {{
        if (selected_scenarios.length === 0) {{
            showToast("No scenarios selected.");
            return;
        }}
        var scenarios_data = [];
        selected_scenarios.forEach(function (scenario_id) {{
            var scenario_data = network.body.data.nodes.get(scenario_id).data;
            scenarios_data.push(scenario_data);
        }});
        var json_data = JSON.stringify(scenarios_data, null, 2);

        // Use fetch to send data to Streamlit
        fetch('/save_scenarios', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json',
            }},
            body: JSON.stringify({{asset_name: asset_name, scenarios: json_data}}),
        }})
        .then(response => {{
            if (!response.ok) {{
                throw new Error(`HTTP error! status: ${{response.status}}`);
            }}
            return response.json();
        }})
        .then(data => {{
            if (data.status === 'success') {{
                console.log('Success:', data.message);
                showToast(data.message); 
            }} else {{
                console.error('Error:', data.message);
                showToast(data.message);
            }} 
        }})
        .catch((error) => {{
            console.error('Fetch Error:', error);
            showToast('Error saving scenarios. See console for details.');
        }});
    }}
    </script>
    """

    with open(output_path, "a") as file:
        file.write(interaction_script)

    buttons_html = """
    <div id="buttons-container" style="position: absolute; top: 10px; right: 10px; z-index: 10;">
        <button onclick="zoomIn()" style="background-color: #444; color: white; border: none; padding: 10px;">Zoom In</button>
        <button onclick="zoomOut()" style="background-color: #444; color: white; border: none; padding: 10px;">Zoom Out</button>
        <button onclick="maximize()" style="background-color: #444; color: white; border: none; padding: 10px;">Maximize</button>
        <button onclick="saveAsPNG()" style="background-color: #444; color: white; border: none; padding: 10px;">Save as PNG</button>
    </div>
    """

    with open(output_path, "r") as file:
        filedata = file.read()

    filedata = filedata.replace('<div id="mynetwork"', '<div id="graph-legend-container"><div id="graph-container"><div id="mynetwork"')
    filedata = filedata.replace('</body>', buttons_html + legend_html + '</body>')

    with open(output_path, "w") as file:
        file.write(filedata)

def display_attackgraph_html_files(html_dir):
    """
    Function to display HTML files from a specified directory in a Streamlit app.

    Parameters:
    html_dir (str): Directory where the generated HTML files are stored.
    """
    # Function to read HTML file content
    def get_html_content(file_path):
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()

    # List all HTML files in the directory
    html_files = [f for f in os.listdir(html_dir) if f.endswith('.html')]

    # Handle case where no HTML files are found
    if not html_files:
        st.warning("No attack graph HTML files found in the directory.")
        st.stop()

    # Create a mapping from display names to actual file names
    display_names = [f[:-5] for f in html_files]  # Remove the ".html" postfix

    # Dropdown to select an asset
    selected_display_name = st.selectbox("Select an Asset", display_names)

    # Map the selected display name back to the actual file name
    selected_asset = html_files[display_names.index(selected_display_name)]

    # Read and display the selected HTML file
    if selected_asset:
        html_path = os.path.join(html_dir, selected_asset)
        html_content = get_html_content(html_path)
        st.components.v1.html(html_content, height=760, scrolling=True)

st.markdown(
    """
    This tab visualizes the attack graph for each asset, illustrating the relationships between assets, threats, attack vectors, and scenarios. The graph dynamically displays interconnected nodes, detailing the progression from initial threats to potential attack scenarios and corresponding controls, enabling a comprehensive analysis of potential attack paths.
    """
)
st.markdown("""---""")

# Path to your unified attack model JSON file
base_path = os.getcwd()
unified_attack_model_path = os.path.join(base_path, "unified_attack_model.json")

generate_graphs_button = st.button("Generate Attack Graphs")
if generate_graphs_button:
    if not os.path.exists(unified_attack_model_path):
        st.error("Unified attack model JSON file does not exist. Please generate the attack model first in the 'Attack Model' tab.")
    else:
        try:
            with open(unified_attack_model_path, "r") as file:
                data = json.load(file)
        except Exception as e:
            st.error(f"Error loading unified attack model JSON file: {e}")
            st.stop()

        output_dir = os.path.join(base_path, "attackgraph-codes\\.attack-g")
        os.makedirs(output_dir, exist_ok=True)

        try:
            with st.spinner("Generating attack graphs..."):
                for asset in data["assets"]:
                    create_attack_graph(asset, output_dir)
            st.success("Attack graphs generated successfully.")
        except Exception as e:
            st.error(f"Error creating attack graphs: {e}")
            st.stop()

        display_attackgraph_html_files(output_dir)


def allow_cors(func):
    """Decorator to wrap Streamlit functions and allow CORS."""
    def wrapper(*args, **kwargs):
        html(
            """
            <script>
            const originalFetch = window.fetch;
            window.fetch = async (...args) => {
                const response = await originalFetch(...args);
                if (!response.headers.has('Access-Control-Allow-Origin')) {
                    response.headers.set('Access-Control-Allow-Origin', '*'); // Allow all origins
                }
                return response;
            };
            </script>
            """
        )
        return func(*args, **kwargs)
    return wrapper

@allow_cors  
@st.cache_resource
def save_scenarios(asset_name, scenarios_data):
    try:
        scenarios_data = json.loads(scenarios_data)
        output_dir = os.path.join(os.getcwd(), "attackgraph-codes", ".attack-g")
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{asset_name}_selected_scenarios.json")
        with open(output_path, "w") as file:
            json.dump(scenarios_data, file, indent=2)
        return "Scenarios saved successfully."
    except (json.JSONDecodeError, Exception) as e:
        return f"Error saving scenarios: {e}"

# # Simulate a Streamlit form submission endpoint
# if st.query_params:
#     query_params = st.query_params
#     if "json_data" in query_params and "asset_name" in query_params:
#         try:
#             # Decode the JSON data and asset name
#             json_data = json.loads(query_params["json_data"][0])
#             asset_name = query_params["asset_name"][0]

#             # Define the output directory
#             output_dir = os.path.join(os.getcwd(), "attackgraph-codes\\.attack-g")

#             # Save the JSON data to a file
#             save_scenarios(json_data, asset_name, output_dir)
#         except json.JSONDecodeError as e:
#             st.error(f"Error decoding JSON data: {e}")
#             st.write(f"Received JSON data: {query_params['json_data'][0]}")
#         except Exception as e:
#             st.error(f"Error: {e}")
