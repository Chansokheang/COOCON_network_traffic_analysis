// background.js

// Store the tab IDs that are currently being debugged and their logs
const debuggingSessions = new Map(); // tabId -> { logs: [] }

const DEBUGGER_PROTOCOL_VERSION = "1.3";

function saveLogsForTab(tabId) {
  const session = debuggingSessions.get(tabId);
  if (session && session.logs && session.logs.length > 0) {
    const logsToSave = [...session.logs]; // Create a copy
    console.log(`Preparing to save ${logsToSave.length} log entries for tab ${tabId}.`);

    try {
      const dataString = JSON.stringify(logsToSave, null, 2); // Pretty print JSON
      // Use a Data URL instead of Blob URL
      const dataUrl = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataString);
      
      chrome.downloads.download({
        url: dataUrl,
        filename: `network_log_tab_${tabId}_${Date.now()}.json`, // Unique filename
        saveAs: true // Prompts user for location
      }, (downloadId) => {
        if (chrome.runtime.lastError) {
          console.error(`Error initiating download for tab ${tabId}: ${chrome.runtime.lastError.message}`);
        } else {
          console.log(`Download initiated for tab ${tabId} with downloadId: ${downloadId}`);
        }
        // No URL.revokeObjectURL(url) needed for data URLs
      });
    } catch (e) {
      // This console.error is the one shown in your screenshot
      console.error(`Error processing or saving logs for tab ${tabId}:`, e);
    }
    // Clear logs for this session after attempting to save
    session.logs = []; 
  } else {
    console.log(`No logs to save for tab ${tabId}, or session not found.`);
  }
}

function attachDebugger(tabId) {
  if (debuggingSessions.has(tabId)) {
    console.log(`Debugger already attached or pending for tab ${tabId}.`);
    return;
  }
  debuggingSessions.set(tabId, { logs: [] }); // Initialize logs for this tab

  chrome.debugger.attach({ tabId: tabId }, DEBUGGER_PROTOCOL_VERSION, () => {
    if (chrome.runtime.lastError) {
      console.error(`Error attaching debugger to tab ${tabId}: ${chrome.runtime.lastError.message}`);
      debuggingSessions.delete(tabId); // Clean up if attach failed
      return;
    }
    console.log(`Debugger attached to tab ${tabId}`);
    chrome.action.setTitle({ tabId: tabId, title: "Stop Capturing Network Traffic (click to save)" });
    
    chrome.debugger.sendCommand({ tabId: tabId }, "Network.enable", {}, () => {
      if (chrome.runtime.lastError) {
        console.error(`Error enabling Network domain for tab ${tabId}: ${chrome.runtime.lastError.message}`);
      } else {
        console.log(`Network domain enabled for tab ${tabId}. Capturing started.`);
      }
    });
  });
}

function detachDebugger(tabId, shouldSaveLogs = true) {
  if (!debuggingSessions.has(tabId) && shouldSaveLogs) {
      console.log(`No active debugging session found for tab ${tabId} to detach and save.`);
      chrome.action.setTitle({ tabId: tabId, title: "Start Capturing Network Traffic" });
      return;
  }

  if (shouldSaveLogs) {
    saveLogsForTab(tabId);
  } else {
    const session = debuggingSessions.get(tabId);
    if (session) session.logs = [];
    console.log(`Logs for tab ${tabId} will not be saved.`);
  }

  chrome.debugger.detach({ tabId: tabId }, () => {
    if (chrome.runtime.lastError) {
      console.error(`Error detaching debugger from tab ${tabId}: ${chrome.runtime.lastError.message}`);
    } else {
      console.log(`Debugger detached from tab ${tabId}`);
    }
    debuggingSessions.delete(tabId);
    chrome.action.setTitle({ tabId: tabId, title: "Start Capturing Network Traffic" });
  });
}

chrome.action.onClicked.addListener((tab) => {
  if (!tab.id) {
    console.error("Clicked on action but tab ID is missing.");
    return;
  }
  const tabId = tab.id;
  if (debuggingSessions.has(tabId) && debuggingSessions.get(tabId).logs !== undefined) {
    detachDebugger(tabId, true);
  } else {
    attachDebugger(tabId);
  }
});

chrome.debugger.onEvent.addListener((debuggeeId, message, params) => {
  const tabId = debuggeeId.tabId;
  if (!tabId || !debuggingSessions.has(tabId)) {
    return;
  }

  const session = debuggingSessions.get(tabId);
  session.logs.push({
    type: message,
    timestamp: new Date().toISOString(),
    data: params 
  });
});

chrome.debugger.onDetach.addListener((debuggeeId) => {
  const tabId = debuggeeId.tabId;
  if (tabId && debuggingSessions.has(tabId)) {
    console.log(`Debugger detached from tab ${tabId} unexpectedly (e.g., DevTools opened, tab closed).`);
    saveLogsForTab(tabId); 
    debuggingSessions.delete(tabId);
    chrome.action.setTitle({ tabId: tabId, title: "Start Capturing Network Traffic" });
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (debuggingSessions.has(tabId)) {
    console.log(`Tab ${tabId} was removed. Detaching debugger and attempting to save logs.`);
    if (debuggingSessions.has(tabId)) {
        detachDebugger(tabId, true);
    }
  }
});

console.log("Network Traffic Capturer background script loaded (v1.2 with Data URL save).");