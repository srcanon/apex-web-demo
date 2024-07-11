# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
import subprocess
import os
import time
import sys
from threading import Thread
DEBUG = True
resource_server_thread = None
client_server_thread = None
client_server_stdin = None

def create_log_folder(id):
    if not os.path.exists("./logs/launcher/" + id):
        os.makedirs("./logs/launcher/" + id,exist_ok=True)
        

def get_log_files():
    id = str(int(time.time_ns() / 1000000))
    create_log_folder(id)
    log_files = {}
    log_files["resource_server"] = "./logs/launcher/" + id + "/resource-server-launcher.log"
    log_files["client_server"] = "./logs/launcher/" + id + "/client-server-launcher.log"
    log_files["pa_server"] = "./logs/launcher/" + id + "/pa-server-launcher.log"
    return log_files

def start_client_server(logfile):
    log_file_fd = open(logfile,"a")
    start_cmd = ["flask","--app","client-server", "run","--host", "127.0.0.2"]
    if(DEBUG):
        start_cmd.append("--debug")
    try:
        subprocess.run(start_cmd,check=True,stdout=log_file_fd,stderr=log_file_fd)
    except Exception as e:
        print("Exception in client server")
        launch_client_server(logfile)
    
def start_resource_server(logfile):
    log_file_fd = open(logfile,"a")
    start_cmd = ["flask","--app","resource-server", "run","--host", "127.0.0.1"]
    if(DEBUG):
        start_cmd.append("--debug")
    try:
        subprocess.run(start_cmd,check=True,stdout=log_file_fd,stderr=log_file_fd)
    except Exception as e:
        print("Exception in resource server")
        launch_resource_server(logfile)

def start_pa_server(logfile):
    log_file_fd = open(logfile,"a")
    start_cmd = ["flask","--app","pa-server", "run","--host", "127.0.0.3"]
    if(DEBUG):
        start_cmd.append("--debug")
    try:
        subprocess.run(start_cmd,check=True,stdout=log_file_fd,stderr=log_file_fd)
    except Exception as e:
        print("Exception in pa server")
        print(e.message)
        launch_resource_server(logfile)

def launch_resource_server(logfile):
    resource_server_thread = Thread(target=start_resource_server, args=[logfile])
    resource_server_thread.start()    

def launch_client_server(logfile):
    client_server_thread = Thread(target=start_client_server, args=[logfile])
    client_server_thread.start()  
def launch_pa_server(logfile):
    pa_server_thread = Thread(target=start_pa_server, args=[logfile])
    pa_server_thread.start()

if __name__ == "__main__":
    log_files =get_log_files()
    launch_resource_server(log_files["resource_server"])
    launch_client_server(log_files["client_server"])
    launch_pa_server(log_files["pa_server"])
    #while(True):
    #    cmd = input(">")
    #    if cmd == "exit":
    #        resource_server_stdin.write()