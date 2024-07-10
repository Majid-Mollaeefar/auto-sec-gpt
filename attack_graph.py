import json
import streamlit as st
import os
from pyvis.network import Network

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

    # Add custom interaction JavaScript manually
    interaction_script = f"""
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script type="text/javascript">
    network.on("dragEnd", function (params) {{
        var nodeId = params.nodes[0];
        if (nodeId) {{
            network.body.data.nodes.update({{id: nodeId, fixed: {{x: true, y: true}}}});
        }}
    }});
    network.on("click", function (params) {{
        var nodeId = params.nodes[0];
        if (nodeId) {{
            var connectedEdges = network.getConnectedEdges(nodeId);

            connectedEdges.forEach(function (edgeId) {{
                network.body.data.edges.update({{id: edgeId, hidden: false}});
                
                var connectedNodeId = network.getConnectedNodes(edgeId);
                for (var i = 0; i < connectedNodeId.length; i++){{
                    if(connectedNodeId[i] != nodeId){{
                        network.body.data.nodes.update({{id: connectedNodeId[i], hidden: false}});
                    }}
                }}
            }});
        }}
    }});

    function zoomIn() {{
        var scale = network.getScale();
        network.moveTo({{ scale: scale + 0.1 }});
    }}

    function zoomOut() {{
        var scale = network.getScale();
        network.moveTo({{ scale: scale - 0.1 }});
    }}

    function maximize() {{
        var container = document.getElementById('graph-legend-container');
        if (container.requestFullscreen) {{
            container.requestFullscreen();
        }} else if (container.mozRequestFullScreen) {{
            container.mozRequestFullScreen();
        }} else if (container.webkitRequestFullscreen) {{
            container.webkitRequestFullscreen();
        }} else if (container.msRequestFullscreen) {{ 
            container.msRequestFullscreen();
        }}
    }}

    function saveAsPNG() {{
        html2canvas(document.getElementById('graph-legend-container')).then(canvas => {{
            var link = document.createElement('a');
            link.href = canvas.toDataURL();
            link.download = '{asset_name}-Attack-graph.png';
            link.click();
        }});
    }}
    </script>
    """

    with open(output_path, "a") as file:
        file.write(interaction_script)

    # Add buttons for zooming, maximizing, and saving as PNG
    buttons_html = """
    <div style="position: absolute; top: 10px; right: 10px; z-index: 10;">
        <button onclick="zoomIn()" style="background-color: #444; color: white; border: none; padding: 10px;">Zoom In</button>
        <button onclick="zoomOut()" style="background-color: #444; color: white; border: none; padding: 10px;">Zoom Out</button>
        <button onclick="maximize()" style="background-color: #444; color: white; border: none; padding: 10px;">Maximize</button>
        <button onclick="saveAsPNG()" style="background-color: #444; color: white; border: none; padding: 10px;">Save as PNG</button>
    </div>
    """

    with open(output_path, "r") as file:
        filedata = file.read()

    filedata = filedata.replace('<div id="mynetwork"', '<div id="graph-legend-container"><div id="graph-container"><div id="mynetwork"')

    filedata = filedata.replace('</body>', buttons_html + '</body>')

    with open(output_path, "w") as file:
        file.write(filedata)

    # Add legend box
    legend_html = """
    <div id="legend-container" style="position: absolute; bottom: 10px; left: 10px; z-index: 10; background-color: #444; color: white; padding: 10px; border: 2px dashed gray;">
        <h4>Legend</h4>
        <p><span style="color: #0000ff;">&#x25A0;</span> Asset</p>
        <p><span style="color: #ff0000;">&#x25C6;</span> Threat</p>
        <p><span style="color: #ff8080;">&#x25CF;</span> Attack Vector</p>
        <p><span style="color: #ffa500;">&#x2B2C;</span> Scenario</p>
        <p><span style="color: #00ff00;">&#x25A0;</span> Control</p>
    </div>
    </div>
    """

    with open(output_path, "r") as file:
        filedata = file.read()

    filedata = filedata.replace('<div id="graph-container">', '<div id="graph-container">' + legend_html)

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

#  Example Usage

# # Specify the path to your attack_model JSON file (unified version of attack_model) 
# json_file_path = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\attackgraph-codes\\unified_attack_model.json"

# # Load data directly from the JSON file (no directory listing needed)
# with open(json_file_path, "r") as file:
#     data = json.load(file)

# # Create the output directory if it doesn't exist where the html data will save
# output_dir = "C:\\Users\\mmoll\\Desktop\\Py\\Threat-Model\\random-coding\\attackgraph-codes\\.attack-g"
# os.makedirs(output_dir, exist_ok=True)

# # Create attack graphs for each asset in the JSON file
# for asset in data["assets"]:
#     create_attack_graph(asset, output_dir)
