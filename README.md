# APEX Proof of Concept
This repository holds the development work for an APEX proof of concept.

There will be 2 phases of development
1. Non-APEX implementation of proof-of concept
2. APEX implementation on top of the above - ideally allowing side-by-side usage to allow evaluation efficiency, but in case that is not possible the non-APEX implementation will be tagged so that it can be forked at a later date if required.

## Current Status - Phase 1
An initial non-APEX implementation of the proof-of-concept app - a note taking app that stores notes on a third-party storage service has been implemented. It consists of the following:
* Resource Server
    * Implements both Username/Password Login and OAuth 2.0 
    * Provides a Registration and Login UI for users
    * Provides a client UI to manage the files stored based on an API that is protected both by conventional session based login and OAuth
    * Provides a developer UI to register OAuth 2.0 clients
* Client Server
    * Implements Username/Password session login for users
    * Provides a UI to Register and Login for users
    * Provides a linking UI for a user to link their account at the Resource Server to their account on the Client Server, i.e. OAuth authorization
    * Provides a UI for creating, viewing and editing notes

## Current Status - Phase 2
* APEX Register and Retrieval are implemented
* You need to be logged into the Client and Server prior to running the demo as it currently does not trigger login redirects, but will do in the future
* Notes can be created, edited and saved
* Deletion is not currently implemented, but is not core to APEX

### Still to implement
* __Token refresh and error handling when a token has expired - this is the most urgent aspect to implement as that workflow currently doesn't exist. As such, the demo works fine on an unlinked account, but may have problems when a token expires__
* The Resource Server UI currently scales instead of being fixed with internal scrollbars
* Breadcrumbs in the UI are currently a placeholder only
* Buttons for creation and upload need to be repositioned
* Deletion method needs implementing (currently GET (retrieve), PUT (edit), POST (new) are implemented)

__Note: the demo has placeholder credentials to allow ease of use. Any security credentials configured within the source code are only for the local development servers and they do not pose a security risk as they are not real credentials to a real service.__

## Running the Demo
1. Ensure Python 3.7 or above is installed and `pipenv` is installed
2. Check out this repository
3. Run `pipenv install`
4. Run `pipenv shell` (2 shells will be required)
5. Run `python3 launch.py` which will launch all three servers and redirect their outputs to log files

## Using the Demo

### Create User Accounts
* Resource Server
    * Client App Developer
        * user: dev@example.com
        * password: `devpassword`
    * User Account
        * user: alice@example.com
        * password: `password`
* Client Server
    * User Account
        * user: alice@example.com
        * password: `notepassword`

### Register as a client of the Resource Server (Developer menu)
* Login as dev@example.com
* Go to the developer tab, and click `Create Client`
* client uri can be anything, for now: `http://127.0.0.2:5000`
* redirect uri: `http://127.0.0.2:5000/authorize`
* pk_endpoint: `http://127.0.0.2:5000/pk_endpoint`
* leave the rest a defaults

Go back to the developer tab and copy the client_id and client_secret to `__init__.py` in the client-server directory, and restart the Client.

__Log out of the Resource Server and either log in as alice or leave it logged out, otherwise you will link the developer account - it will still work but wouldn't be realistic scenario__

### Login as Alice on the client-server
* Click the `LINK TO MYDRIVE` button
* Complete the consent screen - logging in if necessary
* Create a new note - don't forget to hit the save button in the top left of the editor to save any changes.


