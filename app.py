import streamlit as st
import json
import os
from datetime import datetime
from filter_rule_based import filter_network_log_by_dynamic_url
from llm import NetworkLogAnalyzer

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

    if uploaded_file is not None:
        # Save uploaded file
        input_file = save_uploaded_file(uploaded_file)
        if input_file:
            st.success(f"File uploaded successfully: {input_file}")
            
            # Rule-based Filtering Section
            st.header("3. Rule-based Filtering")
            if st.button("Start Rule-based Filtering"):
                with st.spinner("Filtering network logs..."):
                    # Generate output filename with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    filtered_file = f"filtered_network_log_{timestamp}.json"
                    
                    # Run rule-based filtering with extra_keywords
                    filter_network_log_by_dynamic_url(input_file, filtered_file, extra_keywords=extra_keywords)
                    
                    # Display filtered results
                    try:
                        with open(filtered_file, 'r', encoding='utf-8') as f:
                            filtered_data = json.load(f)
                            st.success(f"✅ Filtered {len(filtered_data)} requests")
                            
                            # Display some statistics
                            col1, col2 = st.columns(2)
                            with col1:
                                st.metric("Total Requests", len(filtered_data))
                            with col2:
                                st.metric("Filtered Requests", len(filtered_data))
                            
                            # Show sample of filtered data
                            st.subheader("Sample of Filtered Data")
                            st.json(filtered_data[:3])  # Show first 3 entries
                            
                            # LLM Analysis Section
                            st.header("4. AI Analysis")
                            st.markdown("""
                            The AI will analyze the filtered data to identify the 5 most critical authentication-related requests.
                            """)
                            
                            if st.button("Start AI Analysis"):
                                if not api_key:
                                    st.error("Anthropic API key is required for AI analysis.")
                                else:
                                    st.info("LLM filtering is starting. This may take up to a few minutes depending on the data size and network speed.")
                                    with st.spinner("LLM is analyzing the filtered data. Please wait..."):
                                        try:
                                            # Initialize analyzer with user-provided API key
                                            analyzer = NetworkLogAnalyzer(api_key=api_key)
                                            
                                            # Analyze critical keys
                                            critical_keys = analyzer.analyze_critical_keys(filtered_data)
                                            
                                            # Filter data using critical keys
                                            critical_objects = analyzer.filter_by_critical_keys(filtered_data, critical_keys)
                                            
                                            # Display results
                                            st.success(f"✅ Found {len(critical_keys)} critical requests")
                                            
                                            # Show critical requests
                                            st.subheader("Critical Requests")
                                            for i, obj in enumerate(critical_objects, 1):
                                                with st.expander(f"Critical Request {i}"):
                                                    st.json(obj)
                                            
                                            # Save results
                                            output_file = f"critical_requests_{timestamp}.json"
                                            analyzer.save_results(critical_objects, output_file)
                                            st.success(f"✅ Results saved to {output_file}")
                                            st.success("LLM filtering complete!")
                                            
                                        except Exception as e:
                                            st.error(f"Error during AI analysis: {str(e)}")
                    
                    except Exception as e:
                        st.error(f"Error reading filtered data: {str(e)}")

if __name__ == "__main__":
    main() 