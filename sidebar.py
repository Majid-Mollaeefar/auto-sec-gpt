# sidebar_config.py
import streamlit as st

def configure_sidebar(headers):
    # Generate CSS for each header
    css = "<style>"
    for idx, (header_text, header_color) in enumerate(headers):
        css += f"""
        .header-{idx} {{
            color: {header_color};
        }}
        """
    css += "</style>"
    st.sidebar.markdown(css, unsafe_allow_html=True)

    # Store headers for later use
    st.session_state['headers'] = headers

def render_header(header_index):
    headers = st.session_state.get('headers', [])
    if header_index < len(headers):
        header_text, _ = headers[header_index]
        st.sidebar.markdown(f'<h2 class="header-{header_index}">{header_text}</h2>', unsafe_allow_html=True)