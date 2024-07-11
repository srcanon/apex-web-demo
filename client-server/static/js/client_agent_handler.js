// SPDX-License-Identifier: Apache-2.0 
// Copyright 2024 REDACTED FOR REVIEW
window.addEventListener(
    "load",
    (event) => {
    },
    false
);
var iframeDiv;
var modalDiv;
var dataToProcess = null;
var clientAgentFrame;

//TODO add security check
window.addEventListener(
    "message",
    (event) => {
        
        processMessage(event.data);
    },
    false
);
function processMessage(data) {
    if (data["action"] == "GetData") {
        const send = {};
        send["action"] = "ReceiveData";
        send["data"] = dataToProcess;        
        send["process"] = data["process"];
        const sendMsg = JSON.stringify(send);
        clientAgentFrame.postMessage(sendMsg, "*");//contentWindow
    }else if(data["action"]=="Complete" && data["process"]=="Register"){
        closeClientAgent();
        refreshNotesList();
    }else if(data["action"]=="Complete" && data["process"]=="Save"){
        closeClientAgent();
        endSave = performance.now();
        calculateTimings();
        refreshNotesList();
        M.toast({ html: 'File Saved!', classes: 'rounded' });
    }else if(data["action"]=="Complete" && data["process"]=="Retrieve"){
        closeClientAgent();
        updateEditor(JSON.parse(data["data"]));
    }
}
function startClientAgent(action, data) {
    dataToProcess = data;
    var left = (screen.width / 2) - (500 / 2);
    var top = (screen.height / 2) - (500 / 2);
    clientAgentFrame = window.open("/clientAgent?action=" + action,"CAWindow","width=500px,height=500px, top=" + top + ", left=" + left)
}
function closeClientAgent() {
    clientAgentFrame.close();
}