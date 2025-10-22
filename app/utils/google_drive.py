"""
Google Drive integration for password security checks.
This module provides functionality to check if a password exists in the user's Google Drive.
"""
import os
import re
from typing import List, Optional, Dict, Any
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import io
import json

# If modifying these scopes, delete the token.json file.
SCOPES = ['https://www.googleapis.com/auth/drive.metadata.readonly',
          'https://www.googleapis.com/auth/drive.readonly']

class GoogleDriveScanner:
    """Handles scanning Google Drive for saved passwords."""
    
    def __init__(self, token_path: str = 'token.json', credentials_path: str = 'credentials.json'):
        """
        Initialize the Google Drive scanner.
        
        Args:
            token_path: Path to store the user's access and refresh tokens
            credentials_path: Path to the client secrets file
        """
        self.token_path = token_path
        self.credentials_path = credentials_path
        self.creds = None
        self.service = None
        
    def _get_credentials(self) -> bool:
        """Get valid user credentials from storage or prompt for login."""
        if os.path.exists(self.token_path):
            self.creds = Credentials.from_authorized_user_file(self.token_path, SCOPES)
        
        # If there are no (valid) credentials available, let the user log in.
        if not self.creds or not self.creds.valid:
            if self.creds and self.creds.expired and self.creds.refresh_token:
                try:
                    self.creds.refresh(Request())
                except:
                    return False
            else:
                if not os.path.exists(self.credentials_path):
                    return False
                
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_path, SCOPES)
                self.creds = flow.run_local_server(port=0)
                
                # Save the credentials for the next run
                with open(self.token_path, 'w') as token:
                    token.write(self.creds.to_json())
                    
        return True
    
    def _initialize_service(self) -> bool:
        """Initialize the Google Drive service."""
        if not self._get_credentials():
            return False
            
        try:
            self.service = build('drive', 'v3', credentials=self.creds)
            return True
        except Exception as e:
            print(f"Failed to initialize Google Drive service: {e}")
            return False
    
    def search_files(self, query: str, mime_type: str = None) -> List[Dict[str, Any]]:
        """Search for files in Google Drive."""
        if not self.service and not self._initialize_service():
            return []
            
        try:
            results = self.service.files().list(
                q=f"name contains '{query}'" + (f" and mimeType='{mime_type}'" if mime_type else ''),
                pageSize=10, 
                fields="files(id, name, mimeType)"
            ).execute()
            return results.get('files', [])
        except Exception as e:
            print(f"Error searching files: {e}")
            return []
    
    def download_file(self, file_id: str) -> Optional[str]:
        """Download file content from Google Drive."""
        if not self.service and not self._initialize_service():
            return None
            
        try:
            request = self.service.files().get_media(fileId=file_id)
            file = io.BytesIO()
            downloader = MediaIoBaseDownload(file, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
            return file.getvalue().decode('utf-8')
        except Exception as e:
            print(f"Error downloading file: {e}")
            return None
    
    def find_saved_passwords(self, password: str) -> List[Dict[str, str]]:
        """
        Search for the given password in text files, documents, and spreadsheets.
        
        Args:
            password: The password to search for
            
        Returns:
            List of files containing the password with their details
        """
        if not password or len(password) < 4:  # Skip very short passwords
            return []
            
        if not self.service and not self._initialize_service():
            return []
            
        try:
            # Search in text files
            text_files = self.search_files(password, 'text/plain')
            
            # Search in Google Docs
            docs = self.search_files(password, 'application/vnd.google-apps.document')
            
            # Search in Google Sheets
            sheets = self.search_files(password, 'application/vnd.google-apps.spreadsheet')
            
            # Combine all results
            all_files = text_files + docs + sheets
            
            # Check file contents for the exact password match
            results = []
            for file in all_files:
                content = self.download_file(file['id'])
                if content and password in content:
                    # Simple check to avoid false positives in large files
                    if len(content) < 1000000:  # Skip files larger than 1MB
                        results.append({
                            'id': file['id'],
                            'name': file['name'],
                            'type': file['mimeType'],
                            'snippet': self._get_snippet(content, password)
                        })
                        
            return results
            
        except Exception as e:
            print(f"Error searching for passwords: {e}")
            return []
    
    def _get_snippet(self, content: str, password: str, context: int = 30) -> str:
        """Get a snippet of text around the found password."""
        index = content.find(password)
        if index == -1:
            return ""
            
        start = max(0, index - context)
        end = min(len(content), index + len(password) + context)
        return content[start:end].replace('\n', ' ').strip()

# Singleton instance
google_drive_scanner = GoogleDriveScanner()

def check_password_in_drive(password: str) -> List[Dict[str, str]]:
    ""
    Check if a password exists in the user's Google Drive.
    
    Args:
        password: The password to check
        
    Returns:
        List of files containing the password, or empty list if not found
    """
    try:
        return google_drive_scanner.find_saved_passwords(password)
    except Exception as e:
        print(f"Error checking password in Google Drive: {e}")
        return []
