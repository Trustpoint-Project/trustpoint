#!/usr/bin/env python3
"""Test script for Service Account OAuth 2.0 authentication."""

import requests
import json

# ============================================================================
# CONFIGURATION - Paste your credentials here
# ============================================================================

CLIENT_ID = 'sa_v4XaJVGC3EdOK9xuDELyRiElF_ivHrZWS24iCjvI1Tw'
CLIENT_SECRET = '-sNpXubRcC5UbXPOidbf5i3dIEEJ0rQ39gOQGhJP94dtyePeB4R1hJCsi9mNIL_A'
BASE_URL = 'https://127.0.0.1'  # Use HTTPS to avoid redirect issues

# Token endpoint (same as human users, but with different payload)
TOKEN_ENDPOINT = '/api/token/'

# API endpoint to test
API_ENDPOINT = '/api/devices/'

# SSL/TLS Certificate Options
VERIFY_SSL = False

# ============================================================================
# Script - No need to modify below this line
# ============================================================================

def get_access_token():
    """Request an OAuth 2.0 access token using client credentials grant."""
    token_url = f'{BASE_URL}{TOKEN_ENDPOINT}'
    
    print('\n--- Step 1: Requesting Access Token ---')
    print(f'Token URL: {token_url}')
    print(f'Grant Type: client_credentials')
    print(f'Client ID: {CLIENT_ID}')
    
    try:
        response = requests.post(
            token_url,
            json={
                'grant_type': 'client_credentials',
                'client_id': CLIENT_ID,
                'client_secret': CLIENT_SECRET
            },
            timeout=10,
            verify=VERIFY_SSL
        )
        
        print(f'Status Code: {response.status_code}')
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access')
            token_type = token_data.get('token_type', 'Bearer')
            expires_in = token_data.get('expires_in')
            
            print(f'✓ Token received!')
            print(f'  Token Type: {token_type}')
            if expires_in:
                print(f'  Expires In: {expires_in} seconds')
            print(f'  Access Token: {access_token[:50]}...')
            return access_token
        else:
            print(f'✗ Token request failed')
            print(f'Response: {response.text}')
            return None
            
    except requests.exceptions.RequestException as e:
        print(f'✗ Request failed: {e}')
        return None


def test_api_call():
    """Make an authenticated API call using OAuth 2.0 bearer token."""
    
    print('\nOAuth 2.0 Client Credentials Flow Test')
    print('=' * 70)
    print(f'Base URL: {BASE_URL}')
    print(f'Token Endpoint: {TOKEN_ENDPOINT}')
    print(f'API Endpoint: {API_ENDPOINT}')
    print(f'SSL Verification: {VERIFY_SSL}')
    print('=' * 70)
    
    # Step 1: Get access token
    access_token = get_access_token()
    
    if not access_token:
        print('\n✗ Cannot proceed without access token')
        return
    
    # Step 2: Use access token to make API request
    url = f'{BASE_URL}{API_ENDPOINT}'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }
    
    print('\n--- Step 2: Making API Request with Bearer Token ---')
    print(f'URL: {url}')
    
    try:
        response = requests.get(url, headers=headers, timeout=10, verify=VERIFY_SSL)
        
        print(f'Status Code: {response.status_code}')
        
        if response.status_code == 200:
            print('✓ SUCCESS!')
            print('\nResponse:')
            try:
                data = response.json()
                print(json.dumps(data, indent=2))
            except Exception:
                print(response.text)
        else:
            print('✗ FAILED!')
            print(f'\nError: {response.text}')
            
    except requests.exceptions.RequestException as e:
        print(f'✗ Request failed: {e}')
    
    print('\n' + '=' * 70)
    print('Test Complete')
    print('=' * 70)


if __name__ == '__main__':
    test_api_call()
