# SPDX-License-Identifier: Apache-2.0 
# Copyright 2024 REDACTED FOR REVIEW
RESOURCE_PROFILE_URL = "https://cloud-drive.anon.science/profile/"
RESOURCE_API_URL = "https://cloud-drive.anon.science/api/v1/users/1/files/"
CLIENT_HOST = "cloud-notes.anon.science"
CORS_ORIGINS = origins = [
    "http://localhost",
    "http://127.0.0.1:5000",
    "http://127.0.0.3:5000",
    "http://localhost:5000",
    "http://10.0.2.2:5000",
    "https://cloud-notes.anon.science",
    "https://cloud-drive.anon.science",
    "https://cloud-drive-agent.anon.science",
]
MYDRIVE_CLIENT_ID="4pbte8enfRyOwrwduTKXGAqc"
MYDRIVE_CLIENT_SECRET="MS0p3Uplh6MRenN6oBUtYWoQyWBfgEjD95BH9MxaHzdO7FVx"
MYDRIVE_ACCESS_TOKEN_URL="https://cloud-drive.anon.science/oauth/token"
MYDRIVE_REFRESH_TOKEN_URL="https://cloud-drive.anon.science/oauth/token"
MYDRIVE_AUTHORIZE_URL="https://cloud-drive.anon.science/oauth/authorize?isAPEX=True"
MYDRIVE_CLIENT_KWARGS={'scope': 'full'}
MYDRIVE_API_BASE_URL="https://cloud-drive.anon.science/api/v1/users/"
CRS = "APEXNotesLink"