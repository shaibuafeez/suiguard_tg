from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import os
import requests
import json
import time
import base64
from urllib.parse import urlparse
import google.generativeai as genai
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# Load environment variables
load_dotenv()

app = Flask(__name__, 
           template_folder='app/templates',
           static_folder='app/static')

def check_virustotal(url):
    api_key = os.getenv('VIRUS_TOTAL_API_KEY')
    if not api_key:
        return {"error": "VirusTotal API key not configured"}

    try:
        # First, get the URL ID
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        headers = {
            "x-apikey": api_key,
            "Content-Type": "application/json"
        }

        # Check if URL was already analyzed
        analysis_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        response = requests.get(analysis_url, headers=headers)
        
        # If URL hasn't been analyzed, submit it
        if response.status_code == 404:
            submit_url = "https://www.virustotal.com/api/v3/urls"
            data = {"url": url}
            submit_response = requests.post(submit_url, headers=headers, json=data)
            
            if submit_response.status_code != 200:
                return {"error": f"Failed to submit URL: {submit_response.text}"}
                
            # Wait for analysis
            time.sleep(3)
            response = requests.get(analysis_url, headers=headers)
        
        if response.status_code == 200:
            result = response.json()
            if 'data' in result:
                attributes = result['data']['attributes']
                stats = attributes.get('last_analysis_stats', {})
                
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "clean": stats.get('harmless', 0),
                    "total": sum(stats.values()),
                    "reputation": attributes.get('reputation', 0),
                    "scan_date": attributes.get('last_analysis_date', ''),
                    "categories": attributes.get('categories', {}),
                    "permalink": f"https://www.virustotal.com/gui/url/{url_id}/detection"
                }
        
        return {"error": f"Failed to get analysis: {response.text}"}
        
    except Exception as e:
        return {"error": f"VirusTotal API error: {str(e)}"}

def check_google_safe_browsing(url):
    api_key = os.getenv('GOOGLE_SAFE_BROWSING_KEY')
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    
    payload = {
        "client": {
            "clientId": "suiguard",
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    
    try:
        response = requests.post(api_url, json=payload)
        if response.status_code == 200:
            data = response.json()
            return {
                "threats_found": len(data.get("matches", [])),
                "is_safe": "matches" not in data,
                "details": data.get("matches", [])
            }
    except Exception as e:
        return {"error": str(e)}
    
    return {"is_safe": True, "threats_found": 0}

def check_urlscan(url):
    api_key = os.getenv('URLSCAN_API_KEY')
    if not api_key:
        return {"error": "URLScan API key not configured"}

    # First, try to search for existing scans
    search_headers = {
        'API-Key': api_key,
    }
    
    try:
        # First check if we have an existing scan
        search_url = f'https://urlscan.io/api/v1/search/?q=page.url:"{url}"&size=1'
        search_response = requests.get(search_url, headers=search_headers)
        
        if search_response.status_code == 200:
            search_data = search_response.json()
            if search_data.get('results') and len(search_data['results']) > 0:
                result = search_data['results'][0]
                return {
                    "success": True,
                    "status": "existing",
                    "result_url": result.get('result'),
                    "screenshot": result.get('screenshot'),
                    "message": "Found existing scan results",
                    "risk_level": "info"
                }
    except Exception as e:
        print(f"Search error (non-critical): {str(e)}")

    # If no existing scan found or search failed, try to submit new scan
    headers = {
        'API-Key': api_key,
        'Content-Type': 'application/json',
    }
    
    data = {
        "url": url,
        "visibility": "public",
        "tags": ["suiguard"],
        "customagent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "referer": "https://www.google.com/",
        "country": "US"
    }
    
    try:
        # Submit new scan
        response = requests.post(
            'https://urlscan.io/api/v1/scan/',
            headers=headers,
            json=data,
            timeout=10
        )
        
        if response.status_code == 429:
            return {
                "success": False,
                "error": "Rate limit exceeded. Please try again later."
            }
            
        response_data = response.json()
        
        if response.status_code == 400:
            # If scan is prevented, try to get the domain reputation
            domain = urlparse(url).netloc
            reputation_url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
            rep_response = requests.get(reputation_url, headers=search_headers)
            
            if rep_response.status_code == 200:
                rep_data = rep_response.json()
                if rep_data.get('total', 0) > 0:
                    return {
                        "success": True,
                        "status": "known",
                        "message": "This appears to be a known website",
                        "domain_info": {
                            "total_scans": rep_data.get('total', 0),
                            "domain": domain
                        },
                        "risk_level": "low"
                    }
            
            return {
                "success": False,
                "status": "blocked",
                "message": response_data.get("message", "Scan prevented"),
                "description": response_data.get("description", "Unable to scan this URL"),
                "risk_level": "unknown"
            }
            
        elif response.status_code != 200:
            return {"error": f"Scan submission failed: {response.text}"}
            
        return {
            "success": True,
            "status": "submitted",
            "result_url": response_data.get("result"),
            "scan_id": response_data.get("uuid"),
            "api_url": response_data.get("api"),
            "message": "Scan submitted successfully"
        }
        
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"URLScan error: {str(e)}"}

def init_gemini():
    genai.configure(api_key=os.getenv('GOOGLE_GEMINI_API_KEY'))
    
    # Configure the model
    generation_config = {
        "temperature": 0.9,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 8192,
    }

    # Create the model
    model = genai.GenerativeModel(
        model_name="gemini-2.0-flash-exp",
        generation_config=generation_config
    )
    
    return model

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        url = data.get('url')
        
        if not url:
            return jsonify({"error": "URL is required"}), 400

        results = {
            "url": url,
            "virustotal": check_virustotal(url),
            "google_safe_browsing": check_google_safe_browsing(url),
            "urlscan": check_urlscan(url)
        }
        
        # Calculate overall risk
        vt_result = results["virustotal"]
        gsb_result = results["google_safe_browsing"]
        
        risk_factors = []
        risk_score = 0
        
        if vt_result.get("malicious", 0) > 0:
            risk_score += 40
            risk_factors.append(f"{vt_result['malicious']} security vendors flagged this URL")
            
        if vt_result.get("suspicious", 0) > 0:
            risk_score += 20
            risk_factors.append(f"{vt_result['suspicious']} vendors found suspicious behavior")
            
        if gsb_result.get("threats_found", 0) > 0:
            risk_score += 40
            risk_factors.append("Google Safe Browsing detected threats")
            
        results["risk_score"] = min(risk_score, 100)
        results["risk_factors"] = risk_factors
        
        return jsonify(results)

    except Exception as e:
        return jsonify({
            "error": "Analysis failed",
            "details": str(e)
        }), 500

@app.route('/submit-suspicious', methods=['POST'])
def submit_suspicious():
    data = request.get_json()
    url = data.get('url')
    description = data.get('description')
    
    # Here you would typically save to a database
    # For now, we'll just return a success response
    return jsonify({
        'status': 'success',
        'message': 'Thank you for helping keep the internet safe! Your submission has been recorded.'
    })

@app.route('/ask-assistant', methods=['POST'])
def ask_assistant():
    data = request.get_json()
    question = data.get('question')
    return jsonify({'response': ask_assistant_helper(question)})

def ask_assistant_helper(question):
    try:
        # Initialize Gemini
        model = init_gemini()
        
        # Construct context-aware prompt with system instructions
        context = f"""You are SuiGuard Assistant, an expert cybersecurity analyst and educator with deep expertise in URL analysis, security threat detection, and digital protection. Your role is to help users understand security threats and develop better security practices.

User Question: {question}

Please provide a helpful, clear response. Format your response with numbers for each point, without asterisks or bold text. For example:

1. Use strong passwords: Create complex, lengthy passwords with a mix of uppercase, lowercase, numbers, and symbols. Avoid using personal information.

2. Enable two-factor authentication (2FA): This adds an extra layer of security by requiring a second form of verification when logging into accounts.

Remember to:
- Stay focused on security implications
- Be proactive in identifying potential risks
- Encourage good security habits
- Adapt explanations to user's apparent technical level
- Provide context for all recommendations
- Maintain a balance between thorough analysis and accessibility

Keep the response concise and user-friendly."""
        
        try:
            # Generate response
            response = model.generate_content(context)
            return response.text
            
        except Exception as e:
            print(f"Gemini API Error: {str(e)}")  # Log the actual error
            return f"Error generating response: {str(e)}"
            
    except Exception as e:
        print(f"Server Error: {str(e)}")  # Log the actual error
        return f"Server error occurred: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)