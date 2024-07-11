// SPDX-License-Identifier: Apache-2.0 
// Copyright 2024 REDACTED FOR REVIEW
const API_URL = "/api/v1/users/"
var fs=null;
function getList() {
    const userId = document.getElementById("user_id").value
    var url = API_URL + userId + "/files/"
    fs = new FileSystem(url,document.getElementById("root-files"),document.getElementById("filesPanel"));
    fs.refresh();
}
function refresh(files) {
    const root = document.getElementById("root-files");
    processFolder("/", root, files.children);
    
}
function processFolder(parentPath, parentElement, items) {
    for (var i = 0; i < items.length; i++) {
        const child = items[i];
        if (child.type == "directory") {
            const currentParent = createFolderUI(parentElement, child.name, parentPath);
            processFolder(parentPath + child.name + "/", currentParent, child.children);
        }
    }

}

function createFolderUI(parentElement, folderName, folderPath) {
    const item = document.createElement("li");
    item.addEventListener("click",function(evt) {
        if(this.dataset.showing=="true"){
            const children = this.getElementsByClassName("collapsible");
            const iconElem = this.querySelector("a > span > span.icon > i");
            iconElem.classList.remove("fa-folder-open");
            for(var i=0;i<children.length;i++){
                
                children[i].classList.remove("showing");
                children[i].dataset.showing="false";
            }
            const liChildren = this.getElementsByTagName("li");
            for(var i=0;i<liChildren.length;i++){
                liChildren[i].dataset.showing="false";
            }
            this.dataset.showing="false";
            
        }else{
            const iconElem = this.querySelector("a > span > span.icon > i");
            iconElem.classList.add("fa-folder-open");
            const children = this.childNodes;
            for(var i=0;i<children.length;i++){
                if(children[i].classList.contains("collapsible")){
                    children[i].classList.add("showing");
                }
            }
            this.dataset.showing="true";
        }
        
        evt.stopPropagation();
        
    });
    const link = document.createElement("a");

    const iconText = document.createElement("span");
    iconText.className = "icon-text";
    const iconIcon = document.createElement("span");
    iconIcon.className = "icon";
    const caretIcon = document.createElement("i");
    caretIcon.className = "fa-solid fa-folder";
    iconIcon.appendChild(caretIcon);
    iconText.appendChild(iconIcon);
    const iconLabel = document.createElement("span");
    iconLabel.innerText = folderName;
    iconText.appendChild(iconLabel);
    link.appendChild(iconText);
    item.appendChild(link);



    if (parentElement.id != "root-files") {
        const parentChildren = parentElement.getElementsByTagName("ul");
        var parentSubMenu;
        if (parentChildren.length == 0) {
            parentSubMenu = document.createElement("ul");
            parentSubMenu.classList.add("collapsible");
            parentElement.appendChild(parentSubMenu)

            const iconList = parentElement.getElementsByClassName("fa-folder");

            if (iconList.length > 0) {
                iconList[0].classList.add("fa-folder-plus");
                iconList[0].classList.remove("fa-folder");

            }

        } else {
            parentSubMenu = parentChildren[0];
        }


        parentSubMenu.appendChild(item)
    } else {
        parentElement.appendChild(item)
    }
    return item;



}
function createDirectory() {
    var directoryName = window.prompt("Enter directory name", "New Folder");
    fs.addDirectory(directoryName);
    
}
function uploadFile(){
    fs.addFile();
}
function showFileDialog(){
    const input = document.getElementById("file");
    input.click();
}

class FileSystem {
    constructor(root, renderRoot =null, filesRenderRoot =null){
        this.fileObjectIdx = {}
        this.root = root;
        this.rootFileObject = null;
        this.renderRoot = renderRoot;
        this.filesRenderRoot = filesRenderRoot;
        this.currentFile = null;
    }
    setCurrentFile(currentFile){
        this.currentFile = currentFile;
    }
    addDirectory(directoryName){
        if(this.currentFile!=null && this.currentFile.isFolder()){
            const userId = document.getElementById("user_id").value
            
            var url = API_URL + userId + "/files" + this.currentFile.getPath().replace("/1","") + "/" + directoryName + "/";
            fetch(url, {
                method: "POST"
            })
            .then((response) => response.json())
            .then((data) => console.log(data));
        }
    }
    addFile(){
        if(this.currentFile!=null && this.currentFile.isFolder()){
            const input = document.getElementById("file");
            
            var data = new FormData()
            data.append('file', input.files[0])
            
            const userId = document.getElementById("user_id").value
            
            var url = API_URL + userId + "/files" + this.currentFile.getPath().replace("/1","") + "/" + input.files[0].name ;
            fetch(url, {
                method: "POST",
                body: data
            })
            .then((response) => response.json())
            .then((data) => console.log(data));
        }
    }
    getFilesRenderRoot(){
        return this.filesRenderRoot;
    }
    getPath(){
        return "";
    }
    render(){
        if(this.renderRoot!=null){
            this.renderRoot.innerHTML = "";
            this.renderRoot.appendChild(this.rootFileObject.render(true));
        }
    }
    refresh(){
        fetch(this.root)
        .then((response) => response.json())
        .then((data) => { this._processData(data) });
       
    }
    _processData(data){
        
        this.rootFileObject = new FolderObject(data,this);
        
        this.render();
    }
    getFileSystem(){
        return this;
    }
    getFileObject(path){
        return this.fileObjectIdx[path];
    }
    addFileObject(fileObject){
        this.fileObjectIdx[fileObject.getPath()] = fileObject;
    }
}
class FileSystemObject {
    constructor(data, parentFileObject){
        this.name = data.name;
        this.type = data.type;
        this.path = parentFileObject.getPath() + "/" + this.name;
        this.parent = parentFileObject;        
    }
    render(isRoot=false){
        return null;
    }
    getFileSystem(){
        return this.parent.getFileSystem();
    }
    getParent(){
        return this.parent;
    }
    getName() {
        return this.name;
    }
    getPath(){
        return this.path;
    }
    isFolder(){
        if(this.type=="directory"){
            return true;
        }
        return false;
    }
    isFile(){
        if(this.type=="file"){
            return true;
        }
        return false;
    }
}
class FolderObject extends FileSystemObject {
    constructor(data, parentFileObject) {
        super(data,parentFileObject);
        this.children = [];
        this.childrenIdx = {};
        this._processData(data.children);
        this.directoryViewElem = null;
        this.directoryViewChildrenElem = null;
        this.directoryViewIcon =null;
        this.filesViewElem =null;
        this.isOpen=false;
    }
    showFolder(evt){
        if(this.isOpen && this.children.length>0){
            this.closeFolder();
            this.renderFilesView(this.getFileSystem().getFilesRenderRoot());
        }else{
            this.directoryViewIcon.className = "fa-solid fa-folder-open";
            this.directoryViewChildrenElem.classList.add("showing");
            this.isOpen=true;
            this.renderFilesView(this.getFileSystem().getFilesRenderRoot());
        }
        this.getFileSystem().setCurrentFile(this);
        evt.stopPropagation();
    }
    closeFolder(){
        if(this.children.length>0){
            this.directoryViewIcon.className = "fa-solid fa-folder-plus";
        }else{
            this.directoryViewIcon.className = "fa-solid fa-folder";
        }
        this.directoryViewChildrenElem.classList.remove("showing");
        this.isOpen=false;
        for(const childItem of this.children){
            if(childItem.isFolder()){
                childItem.closeFolder();
            }
        }
    }
    renderFilesView(filesRenderRoot){
        filesRenderRoot.innerHTML="";
        for(const childItem of this.children){
            if(childItem.isFolder()){
                this.filesViewElem = document.createElement("a");
                this.filesViewElem.className ="panel-block";
                const iconSpan = document.createElement("span");
                iconSpan.className="panel-icon";
                const icon = document.createElement("i");
                icon.className = "fa-solid fa-folder";
                icon.ariaHidden = true;
                iconSpan.append(icon);
                this.filesViewElem.append(iconSpan);
                const text = document.createTextNode(childItem.getName());
                this.filesViewElem.appendChild(text);
                filesRenderRoot.appendChild(this.filesViewElem);
            }else{
                filesRenderRoot.appendChild(childItem.renderFilesView());
            }
        }
    }
    render(isRoot = false){
        if(!isRoot){
            
            this.directoryViewElem = document.createElement("li");
            this.directoryViewElem.addEventListener("click",this.showFolder.bind(this));
            this.directoryViewElem.dataset.path = this.getPath();
            const anchor = document.createElement("a");
            const iconText = document.createElement("span");
            iconText.className = "icon-text";
            const iconIcon = document.createElement("span");
            iconIcon.className = "icon";
            this.directoryViewIcon = document.createElement("i");
            if(this.children.length>0){
                this.directoryViewIcon.className = "fa-solid fa-folder-plus";
            }else{
                this.directoryViewIcon.className = "fa-solid fa-folder";
            }
            iconIcon.appendChild(this.directoryViewIcon);
            iconText.appendChild(iconIcon);
            const iconLabel = document.createElement("span");
            iconLabel.innerText = this.getName();
            iconText.appendChild(iconLabel);
            anchor.appendChild(iconText);
            this.directoryViewElem.appendChild(anchor);
            this.directoryViewChildrenElem = document.createElement("ul");
            this.directoryViewChildrenElem.className = "collapsible";
            for(const child of this.children){
                const childElem = child.render();
                if(childElem!=null){
                    this.directoryViewChildrenElem.appendChild(childElem);
                }
            }
            this.directoryViewElem.appendChild(this.directoryViewChildrenElem);
            
        }else{
            this.directoryViewElem = document.createElement("ul");
            this.directoryViewElem.className = "menu-list";
            for(const child of this.children){
                const childElem = child.render();
                if(childElem!=null){
                    this.directoryViewElem.appendChild(childElem);
                    }
            }
        }
            
        
        
        return this.directoryViewElem;
    }
    _processData(data){
        for(var i=0;i<data.length;i++){
            const childData = data[i];
            if(childData.type=="directory"){
                this.addChild(new FolderObject(childData,this));
            }else{
                this.addChild(new FileObject(childData,this));
            }
        }
    }
    addChild(childFileObj){
        this.children.push(childFileObj);
        this.childrenIdx[childFileObj.getName()] = childFileObj;
        this.getFileSystem().addFileObject(childFileObj);
    }
  }
class FileObject extends FileSystemObject{
    constructor(data, parentFileObject) {
        super(data,parentFileObject);
        this.filesViewElem = null;
    }

    renderFilesView(){
        this.filesViewElem = document.createElement("a");
        this.filesViewElem.className ="panel-block";
        const iconSpan = document.createElement("span");
        iconSpan.className="panel-icon";
        const icon = document.createElement("i");
        icon.className = "fa-regular fa-file-lines";
        icon.ariaHidden = true;
        iconSpan.append(icon);
        this.filesViewElem.append(iconSpan);
        const text = document.createTextNode(this.name);
        this.filesViewElem.appendChild(text);
        return this.filesViewElem;
    }
}