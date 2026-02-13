import requests
import json
import time

BASE_URL = 'http://localhost:5000'

def test_health():
    try:
        r = requests.get(f'{BASE_URL}/api/health')
        print(f"Health Check: {r.status_code}")
        print(json.dumps(r.json(), indent=2))
        return r.status_code == 200
    except Exception as e:
        print(f"Health Check Failed: {e}")
        return False

def test_auth_flow():
    # Signup
    signup_data = {
        'username': 'verify_user_' + str(int(time.time())),
        'email': f'verify_{int(time.time())}@example.com',
        'password': 'password123'
    }
    
    print("\nTesting Signup...")
    r_signup = requests.post(f'{BASE_URL}/api/signup', json=signup_data)
    print(f"Signup Status: {r_signup.status_code}")
    print(r_signup.text)
    
    if r_signup.status_code != 201:
        # User might already exist if re-running
        print("Signup failed (possibly user exists), trying login...")
        
    # Login
    login_data = {
        'username': signup_data['username'],
        'password': signup_data['password']
    }
    
    print("\nTesting Login...")
    r_login = requests.post(f'{BASE_URL}/api/login', json=login_data)
    print(f"Login Status: {r_login.status_code}")
    
    if r_login.status_code == 200:
        token = r_login.json().get('token')
        print("Login Successful, Token received.")
        return token
    else:
        print("Login Failed.")
        return None

def test_prediction(token):
    if not token:
        print("Skipping prediction test due to missing token.")
        return

    # Sample features (all 0s for simplicity, or some values)
    features = {
        'NumDots': 3, 'SubdomainLevel': 1, 'PathLevel': 1, 'UrlLength': 50, 
        'NumDash': 0, 'NumDashInHostname': 0, 'AtSymbol': 0, 'TildeSymbol': 0, 
        'NumUnderscore': 0, 'NumPercent': 0, 'NumQueryComponents': 0, 'NumAmpersand': 0, 
        'NumHash': 0, 'NumNumericChars': 0, 'NoHttps': 0, 'RandomString': 0, 
        'IpAddress': 0, 'DomainInSubdomains': 0, 'DomainInPaths': 0, 'HttpsInHostname': 0, 
        'HostnameLength': 10, 'PathLength': 30, 'QueryLength': 0, 'DoubleSlashInPath': 0, 
        'NumSensitiveWords': 0, 'EmbeddedBrandName': 0, 'PctExtHyperlinks': 0, 
        'PctExtResourceUrls': 0, 'ExtFavicon': 0, 'InsecureForms': 0, 'RelativeFormAction': 0, 
        'ExtFormAction': 0, 'AbnormalFormAction': 0, 'PctNullSelfRedirectHyperlinks': 0, 
        'FrequentDomainNameMismatch': 0, 'FakeLinkInStatusBar': 0, 'RightClickDisabled': 0, 
        'PopUpWindow': 0, 'SubmitInfoToEmail': 0, 'IframeOrFrame': 0, 'MissingTitle': 0, 
        'ImagesOnlyInForm': 0, 'SubdomainLevelRT': 1, 'UrlLengthRT': 1, 
        'PctExtResourceUrlsRT': 1, 'AbnormalExtFormActionR': 1, 'ExtMetaScriptLinkRT': 1, 
        'PctExtNullSelfRedirectHyperlinksRT': 1
    }
    
    headers = {'Authorization': f'Bearer {token}'}
    
    print("\nTesting Prediction...")
    r_predict = requests.post(
        f'{BASE_URL}/api/predict', 
        json={'features': features},
        headers=headers
    )
    print(f"Prediction Status: {r_predict.status_code}")
    print(json.dumps(r_predict.json(), indent=2))

if __name__ == "__main__":
    if test_health():
        token = test_auth_flow()
        test_prediction(token)
