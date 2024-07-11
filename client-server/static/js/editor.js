
// SPDX-License-Identifier: Apache-2.0 
// Copyright 2024 REDACTED FOR REVIEW
var toolbarOptions = [
  ['bold', 'italic', 'underline', 'strike'],        // toggled buttons
  ['blockquote', 'code-block'],

  [{ 'header': 1 }, { 'header': 2 }],               // custom button values
  [{ 'list': 'ordered' }, { 'list': 'bullet' }],
  [{ 'script': 'sub' }, { 'script': 'super' }],      // superscript/subscript
  [{ 'indent': '-1' }, { 'indent': '+1' }],          // outdent/indent
  [{ 'direction': 'rtl' }],                         // text direction

  [{ 'size': ['small', false, 'large', 'huge'] }],  // custom dropdown
  [{ 'header': [1, 2, 3, 4, 5, 6, false] }],

  [{ 'color': [] }, { 'background': [] }],          // dropdown with defaults from theme
  [{ 'font': [] }],
  [{ 'align': [] }],

  ['clean']                                         // remove formatting button
];
var quill;
function loadEditor() {
  const isLinked = Boolean(document.getElementById("isLinked").value);

  var options = {
    modules: {
      toolbar: toolbarOptions
    },
    placeholder: 'Select a note to edit or click Create New Note',
    readOnly: true,
    scrollingContainer: '#scrolling-container',
    theme: 'snow'
  };
  if (!isLinked) {
    options.placeholder = "Link to MyDrive to create and edit notes";
    options.readOnly = true;
  }
  quill = new Quill('#quill-container', options);
  const toolbarElem = document.getElementsByClassName("ql-toolbar")[0];
  const block = document.createElement("span");
  block.className = "ql-formats";
  const saveButton = document.createElement("button");
  saveButton.type = "button";
  saveButton.className = "ql-save";

  saveButton.innerHTML = '<svg style="width:18px;height:18px" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512"><!--! Font Awesome Pro 6.3.0 by @fontawesome - https://fontawesome.com License - https://fontawesome.com/license (Commercial License) Copyright 2023 Fonticons, Inc. --><path class="custom-toolbar-button" d="M48 96V416c0 8.8 7.2 16 16 16H384c8.8 0 16-7.2 16-16V170.5c0-4.2-1.7-8.3-4.7-11.3l33.9-33.9c12 12 18.7 28.3 18.7 45.3V416c0 35.3-28.7 64-64 64H64c-35.3 0-64-28.7-64-64V96C0 60.7 28.7 32 64 32H309.5c17 0 33.3 6.7 45.3 18.7l74.5 74.5-33.9 33.9L320.8 84.7c-.3-.3-.5-.5-.8-.8V184c0 13.3-10.7 24-24 24H104c-13.3 0-24-10.7-24-24V80H64c-8.8 0-16 7.2-16 16zm80-16v80H272V80H128zm32 240a64 64 0 1 1 128 0 64 64 0 1 1 -128 0z"/></svg>';
  saveButton.addEventListener("click", function (evt) {
    saveData(quill.getContents());
  });
  block.appendChild(saveButton);
  toolbarElem.insertBefore(block, toolbarElem.firstChild);

  document.getElementsByClassName("ql-editor")[0].classList.add("z-depth-2");
}
function saveDataAPEX(data) {
  submitData = {}
  submitData["name"] = currentNote;
  submitData["data"] = data;

  startClientAgent("register", submitData);
}
var useAPEX = true;
function saveData(data) {
  startSave = performance.now();
  if (currentNoteApex) {
    saveDataAPEX(data);
    return;
  }
  var url = "/notes/save";
  uploadData = {};
  uploadData["data"] = data;
  uploadData["name"] = currentNote;
  fetch(url, {
    body: JSON.stringify(uploadData),
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    }
  })
    .then((response) => response.json())
    .then((data) => saveResponse(data));
}
function calculateTimings() {
  const timing = {};
  timing["start"] = startSave;
  timing["end"] = endSave;
  timing["duration"] = endSave - startSave;
  timing["item"] = currentNote;
  timing["isApex"] = currentNoteApex;
  save_timing_data.push(timing);
}
function saveResponse(data) {
  endSave = performance.now();
  calculateTimings();
  if (data["success"] == true) {
    M.toast({ html: 'File Saved!', classes: 'rounded' });
  }
}
function loadFiles() {
  const isLinked = Boolean(document.getElementById("isLinked").value);
  if (isLinked) {
    refreshNotesList();
  }
}
var lastNoteList = null;
function refreshNotesList() {

  var url = "/notes/list";
  fetch(url)
    .then((response) => response.json())
    .then((data) => updateList(data))
    .catch( err => {
      console.log("Cannot load notes list - may not be linked");
    });
}
function updateList(data) {
  //Crude check for the same list, should do a deep compare
  if(lastNoteList != null && JSON.stringify(lastNoteList) == JSON.stringify(data)){
    return;
  }
  lastNoteList = data;
  const menu = document.getElementById("slide-out");
  const existing = menu.getElementsByClassName("note-file");
  while (existing.length > 0) {
    existing[0].parentNode.removeChild(existing[0]);
  }
  for (const child of data.children) {
    if (child.type == "file" && child.name.endsWith(".note")) {
      const menuItem = document.createElement("li");
      const link = document.createElement("a");
      link.className = "note-file";
      link.innerText = child.name.replace(".note", "");
      link.dataset["name"] = child.name;
      link.addEventListener("click", function (evt) {
        setActiveNote(this);
        getNote(child.name + "");
      });
      menuItem.appendChild(link);
      menu.appendChild(menuItem);
    } else if (child.type == "file" && child.name.endsWith(".note.apex")) {
      const menuItem = document.createElement("li");
      const link = document.createElement("a");
      const icon = document.createElement("i");
      const text = document.createElement("span");
      icon.className = "fa-solid fa-lock file-icon";
      link.className = "note-file";
      text.innerText = child.name.replace(".note.apex", "");
      link.appendChild(text);

      link.appendChild(icon);

      link.dataset["name"] = child.name;
      link.dataset["apex"] = true;
      link.addEventListener("click", function (evt) {
        setActiveNote(this);
        getNote(child.name + "", true);
      });
      menuItem.appendChild(link);
      menu.appendChild(menuItem);
    }
  }

}
var currentNote = "";
var currentNoteApex = false;
function setActiveNote(target) {
  const menu = document.getElementById("slide-out");
  var elems = menu.getElementsByClassName("active");
  for (const elem of elems) {
    elem.classList.remove("active");
  }
  target.parentNode.classList.add("active");
  currentNote = target.dataset.name;
  currentNoteApex = target.dataset.apex;

}
function getNote(name, APEX = false) {
  requestStart = performance.now();
  if (APEX) {
    var target = name;
    var url = "/notes/retrieve_apex?" + new URLSearchParams({ name: target });
    fetch(url)
      .then((response) => response.json())
      .then((data) => {
        data["name"] = target;
        startClientAgent("retrieve", data);

      });
  } else {


    var target = name;
    var url = "/notes/note?" + new URLSearchParams({ name: target });

    fetch(url)
      .then((response) => response.json())
      .then((data) => updateEditor(data));
  }
}
var requestStart;
var requestEnd;
var timing_data = [];
var startSave;
var endSave;
var save_timing_data = [];
function exportSaveTiming() {
  var durations = [];
  console.log(JSON.stringify(save_timing_data));
  var total = 0;
  for (var i = 1; i < save_timing_data.length; i++) {
    durations.push(save_timing_data[i]["duration"])
    total = total + save_timing_data[i]["duration"];
  }
  const result = getStandardDeviation(durations);

  console.log("Average:" + (total / (save_timing_data.length - 1)));
  console.log("Mean:" + result[0]);
  console.log("Std:" + result[1]);

}

function exportTiming() {
  var durations = [];
  console.log(JSON.stringify(timing_data));
  var total = 0;
  for (var i = 1; i < timing_data.length; i++) {
    durations.push(timing_data[i]["duration"])
    total = total + timing_data[i]["duration"];
  }
  const result = getStandardDeviation(durations);

  console.log("Average:" + (total / (timing_data.length - 1)));
  console.log("Mean:" + result[0]);
  console.log("Std:" + result[1]);

}

function getStandardDeviation(array) {
  const n = array.length
  const mean = array.reduce((a, b) => a + b) / n
  const std = Math.sqrt(array.map(x => Math.pow(x - mean, 2)).reduce((a, b) => a + b) / n);
  return [mean, std];
}
function updateEditor(data) {
  requestEnd = performance.now();
  const timing = {};
  timing["start"] = requestStart;
  timing["end"] = requestEnd;
  timing["duration"] = requestEnd - requestStart;
  timing["item"] = currentNote;
  timing["isApex"] = currentNoteApex;
  timing_data.push(timing);
  if (JSON.stringify(data) == "{}") {
    document.getElementsByClassName("ql-editor")[0].dataset.placeholder = "Empty note, click here to start editing";
  }
  quill.setContents(data);
  quill.enable();
}
function createNewNote() {
  var newNoteName = window.prompt("Enter new note name");
  if (newNoteName != null) {
    newNoteName = newNoteName + ".note";
    var url = "/notes/create";
    uploadData = {};
    uploadData["name"] = newNoteName;
    fetch(url, {
      body: JSON.stringify(uploadData),
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      }
    })
      .then((response) => response.json())
      .then((data) => updateList(data));
  }
}
function createNewAPEXNote() {
  var newNoteName = window.prompt("Enter new APEX note name");
  if (newNoteName != null) {
    newNoteName = newNoteName + ".note.apex";
    var data = {};
    data["name"] = newNoteName;
    data["data"] = {};
    data["isNew"] = true;
    startClientAgent("register", data);
  }
}


function startLink() {
  var url = "/link";
  fetch(url)
    .then((response) => response.json())
    .then((data) => showOTP(data));
}
function showOTP(resp) {
  document.getElementById("otpCode").innerText = resp.otp;

  var instance = M.Modal.getInstance(document.getElementById("otpModal"));
  instance.open();
}
function proceedWithLinking() {
  window.location = "/link-authorise";
}
document.addEventListener('DOMContentLoaded', function () {

  var elems = document.querySelectorAll('.modal');
  var instances = M.Modal.init(elems);
});
