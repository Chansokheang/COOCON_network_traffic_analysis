import streamlit as st
import json
import os
from datetime import datetime
from filter_rule_based import filter_network_log_by_dynamic_url
from llm import NetworkLogAnalyzer
import traceback
import io

def save_uploaded_file(uploaded_file):
    """Save uploaded file to 'uploaded_files/' folder, creating it if needed."""
    upload_dir = "uploaded_files"
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, uploaded_file.name)
    try:
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        st.error(f"Error saving file: {str(e)}")
        return None

def main():
    st.set_page_config(
        page_title="Network Log Analyzer",
        page_icon="🔍",
        layout="wide"
    )

    st.title("🔍 Network Log Analyzer")
    st.markdown("""
    This tool helps analyze network logs by:
    1. Filtering out non-essential requests using rule-based filtering
    2. Identifying critical authentication-related requests using AI
    """)

    # Anthropic API Key Input
    st.header("Anthropic API Key")
    api_key = st.text_input("Enter your Anthropic API Key", type="password")
    if not api_key:
        st.info("Please enter your Anthropic API key to enable AI analysis.")

    # File Upload Section
    st.header("1. Upload Network Log")
    uploaded_file = st.file_uploader("Choose a JSON file", type=['json'])

    # Login URL Input Section
    st.header("2. (Optional) Add Login URLs for Filtering")
    login_urls = st.text_area(
        "Enter login/authentication URLs (one per line or comma-separated):",
        placeholder="https://example.com/login\nhttps://example.com/api/auth"
    )
    # Parse user input into a list
    extra_keywords = []
    if login_urls.strip():
        # Split by newlines or commas, strip whitespace
        extra_keywords = [url.strip() for url in login_urls.replace(',', '\n').split('\n') if url.strip()]

    # --- Rule-based Filtering Section ---
    if uploaded_file is not None:
        input_file = save_uploaded_file(uploaded_file)
        if input_file:
            st.success(f"File uploaded successfully: {input_file}")

    if 'filtered_data' not in st.session_state:
        st.session_state.filtered_data = None
    if 'filtered_file' not in st.session_state:
        st.session_state.filtered_file = None
    if 'llm_started' not in st.session_state:
        st.session_state.llm_started = False

    st.header("3. Rule-based Filtering")
    if uploaded_file is not None and st.button("Start Rule-based Filtering"):
        with st.spinner("Filtering network logs..."):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filtered_file = f"filtered_network_log_{timestamp}.json"
            filter_network_log_by_dynamic_url(input_file, filtered_file, extra_keywords=extra_keywords)
            try:
                with open(filtered_file, 'r', encoding='utf-8') as f:
                    filtered_data = json.load(f)
                    st.session_state.filtered_data = filtered_data
                    st.session_state.filtered_file = filtered_file
                    st.success(f"✅ Filtered {len(filtered_data)} requests")
            except Exception as e:
                st.error(f"Error reading filtered data: {str(e)}")
                st.session_state.filtered_data = None
                st.session_state.filtered_file = None

    # --- Show Filtered Data and LLM Section if Available ---
    if st.session_state.filtered_data is not None:
        filtered_data = st.session_state.filtered_data
        st.header("Sample of Filtered Data")
        st.json(filtered_data[:3])  # Show first 3 entries
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Requests", len(filtered_data))
        with col2:
            st.metric("Filtered Requests", len(filtered_data))

        # --- LLM Analysis Section ---
        st.header("4. AI Analysis")
        st.markdown("""
        The AI will analyze the filtered data to identify the 5 most critical authentication-related requests.
        """)

        if st.button("Start AI Analysis"):
            st.session_state.llm_started = True

        if st.session_state.llm_started:
            st.write("LLM analysis started...")
            if not api_key:
                st.error("Anthropic API key is required for AI analysis.")
                st.session_state.llm_started = False
            else:
                try:
                    with st.spinner("LLM is analyzing the filtered data. Please wait..."):
                        analyzer = NetworkLogAnalyzer(api_key=api_key)
                        critical_keys = analyzer.analyze_critical_keys(filtered_data)
                        critical_objects = analyzer.filter_by_critical_keys(filtered_data, critical_keys)
                        st.success(f"✅ Found {len(critical_keys)} critical requests")
                        st.subheader("Critical Requests")
                        for i, obj in enumerate(critical_objects, 1):
                            with st.expander(f"Critical Request {i}"):
                                st.json(obj)
                        output_file = f"critical_requests_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        analyzer.save_results(critical_objects, output_file)
                        st.success(f"✅ Results saved to {output_file}")
                        st.success("LLM filtering complete!")
                        # Add download button
                        with open(output_file, "r", encoding="utf-8") as f:
                            result_json = f.read()
                        st.download_button(
                            label="Download LLM Results",
                            data=result_json,
                            file_name=output_file,
                            mime="application/json"
                        )
                except Exception as e:
                    st.error(f"Error during AI analysis: {str(e)}")
                    st.text(traceback.format_exc())
                st.session_state.llm_started = False

if __name__ == "__main__":
    main() 