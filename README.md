# Network Traffic Capturer Chrome Extension

A Chrome extension that captures network traffic for the active tab and allows saving it as a JSON file for analysis. This extension is part of a complete network analysis workflow that includes rule-based filtering and AI-powered analysis.

## Overview

This Chrome extension uses the Chrome Debugger API to capture all network requests and responses from the active tab. It's designed for developers, security researchers, and network analysts who need to monitor and analyze web traffic, particularly for authentication and login flow analysis.

## Features

- **Real-time Network Capture**: Captures all network requests and responses in real-time
- **Per-tab Monitoring**: Each browser tab can be monitored independently
- **JSON Export**: Saves captured network data as structured JSON files
- **Automatic File Naming**: Generated files include tab ID and timestamp for easy identification
- **Clean Session Management**: Automatically handles cleanup when tabs are closed or debugger is detached

## Installation

1. Open Chrome browser
2. Navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in the top right corner)
4. Click "Load unpacked"
5. Select the `chrome_exe` folder from your file system
6. The extension will appear in your extensions list and toolbar

## Usage

### Starting Network Capture

1. Navigate to the webpage you want to monitor
2. Click the "Network Traffic Capturer" extension icon in the toolbar
3. The extension will start capturing network traffic
4. The icon tooltip will change to "Stop Capturing Network Traffic (click to save)"

### Stopping and Saving Capture

1. Click the extension icon again to stop capturing
2. A file download dialog will appear
3. Choose where to save the network log JSON file
4. The file will be named: `network_log_tab_[TAB_ID]_[TIMESTAMP].json`

### Automatic Saving

The extension automatically saves captured data when:
- The tab is closed
- Chrome DevTools is opened (which detaches the debugger)
- The extension is disabled or removed

## Complete Analysis Workflow

After capturing network traffic with this extension, the data can be processed through a multi-stage filtering pipeline:

### 1. Network Capture (Chrome Extension)
- Captures all network traffic from the active tab
- Exports raw network logs as JSON files

### 2. Rule-Based Filtering (`filter_rule_based.py`)
- Filters out static resources (CSS, JS, images, fonts)
- Focuses on dynamic requests with POST data
- Includes specific URL patterns for authentication flows
- Filters WebSocket frames based on return values
- **Usage**: `python filter_rule_based.py`

### 3. AI-Powered Analysis (`llm.py`)
- Uses Claude AI to identify critical login-related requests
- Analyzes request dependencies and token relationships
- Extracts 3-5 most critical authentication objects
- **Usage**: `python llm.py`

## File Format

The exported JSON file contains an array of network events with the following structure:

```json
[
  {
    "type": "Network.requestWillBeSent",
    "timestamp": "2024-01-01T12:00:00.000Z",
    "data": {
      // Chrome DevTools Protocol network event data
    }
  },
  // ... more network events
]
```

### Processing Pipeline Output

1. **Raw capture**: `network_log_tab_[TAB_ID]_[TIMESTAMP].json`
2. **Rule-filtered**: `filtered_network_log_final_[SITE].json`
3. **AI-filtered**: `filtered_network_log_final_login_[SITE].json`


## Development

### Complete Project Structure
```
project/
├── chrome_exe/              # Chrome Extension
│   ├── manifest.json        # Extension configuration
│   ├── background.js        # Main extension logic
│   └── README.md           # This documentation
├── filter_rule_based.py    # Rule-based filtering script
├── llm.py                  # AI-powered analysis script
├── network_files/          # Raw network capture files
└── output/                 # Processed output files
```

### Processing Scripts

#### Rule-Based Filter (`filter_rule_based.py`)
- **Purpose**: Initial filtering to remove noise and focus on dynamic requests
- **Filters**:
  - Excludes static resources (.js, .css, .png, etc.)
  - Includes specific authentication-related URLs
  - Filters WebSocket frames based on return values
  - Excludes invalid URL schemes (data:, blob:, javascript:)
- **Configuration**: Modify `excluded_extensions` and `included_url_keywords` arrays


## Configuration

### Setting the Anthropic API Key

To use the AI-powered analysis (`llm.py`), you must set your Anthropic API key as an environment variable before running the script.  
On Windows, run this command in your terminal or Command Prompt:

```sh
set ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

On macOS/Linux, use:

```sh
export ANTHROPIC_API_KEY=your_anthropic_api_key_here
```

Replace `your_anthropic_api_key_here` with your actual API key.


#### AI Analysis (`llm.py`)
- **Purpose**: Intelligent identification of critical authentication flows
- **Features**:
  - Analyzes request dependencies and token relationships
  - Identifies authentication, credential submission, and session exchange
  - Extracts most critical login-related objects
  - Uses Claude AI for advanced pattern recognition
- **Requirements**: Anthropic API key for Claude access

### Key Components

- **Background Service Worker**: Handles debugger attachment, network event capture, and file saving
- **Chrome Debugger API**: Provides access to network traffic data
- **Downloads API**: Enables saving captured data as JSON files
- **Rule-Based Filter**: Python script for initial data reduction
- **AI Analysis**: Claude-powered intelligent filtering for authentication flows


## Workflow Example

1. **Install and use the Chrome extension** to capture network traffic
2. **Run rule-based filtering**:
   ```bash
   python filter_rule_based.py
   ```
3. **Run AI analysis** (requires Anthropic API key):
   ```bash
   python llm.py
   ```
4. **Analyze results** in the generated output files

## Support

For issues or questions:
1. Check the browser console for error messages
2. Verify extension permissions are granted
3. Ensure Chrome is up to date
4. Try reloading the extension in chrome://extensions/
5. For processing scripts, ensure Python dependencies are installed
6. For AI analysis, verify Anthropic API key is configured
