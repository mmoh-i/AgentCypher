import os
import requests
from fastapi import FastAPI, HTTPException, Form
from langchain_cohere import ChatCohere
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_community.document_loaders.csv_loader import CSVLoader
import uvicorn
import vt
import base64


# Global variables
model = None
known_scams = []
api_key = os.getenv("VIRUSTOTAL_API_KEY")
if not api_key:
    raise ValueError("VIRUSTOTAL_API_KEY environment variable not set")
client = vt.Client(api_key)
# Initialize FastAPI
app = FastAPI()

def lifespan(app: FastAPI):
    global model, known_scams

    # Load Cohere API key
    api_key = os.getenv("COHERE_API_KEY")
    if not api_key:
        raise ValueError("COHERE_API_KEY environment variable not set")
    model = ChatCohere(model="command-r-plus", api_key=api_key)

    # Load known scams database from CSV
    try:
        file = "urls.csv"
        loader = CSVLoader(file_path=file)
        data = loader.load()
        known_scams = [entry.page_content.lower() for entry in data]
        print(f"Loaded {len(known_scams)} known scams from database.")
    except Exception as e:
        print(f"Error loading CSV database: {e}")
        known_scams = []

    yield  # Server runs here

    # Cleanup (if needed)
    print("Shutting down application...")

app = FastAPI(lifespan=lifespan)

# RugCheck API: Verify token
def check_verified_tokens():
    try:
        url = "https://api.rugcheck.xyz/v1/stats/verified"
        response = requests.get(url, headers={"Accept": "application/json"})
        if response.status_code == 200:
            return response.json()  # List of verified tokens
        else:
            return None
    except Exception as e:
        print(f"Error checking RugCheck API: {str(e)}")
        return None

# VirusTotal API: Scan URL
def scan_url_with_virustotal(scan_url: str):
    try:
        virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not virustotal_api_key:
            raise ValueError("VIRUSTOTAL_API_KEY environment variable not set")

        # VirusTotal API endpoint
        url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": virustotal_api_key}
        data = {"url": scan_url}

        # Send POST request to scan URL
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Failed to scan URL. Status code: {response.status_code}"}
    except Exception as e:
        return {"error": str(e)}

@app.get("/")
async def root():
    return {
        "message": "Hello! I am AgentCypher 🤖, your scam and token verification assistant. Use the endpoints to check scams, verify tokens, or scan URLs.",
        "endpoints": {
            "check_scam": "/api/v1/check_scam/",
            "check_verified_tokens": "/api/v1/verified_tokens/",
            "scan_url": "/api/v1/scan_url/"
        }
    }

# API to check if input text is a scam
@app.post("/api/v1/check_scam/")
async def check_scam(text: str = Form(...)):
    global model, known_scams
    try:
        clean_text = text.lower().strip()
        if any(clean_text in scam for scam in known_scams):
            return {
                "response": "⚠️ This looks like a **known scam** from our database. Stay cautious! 🚨",
                "is_scam": True
            }

        # Use AI model for analysis
        system_message = SystemMessage(
            content="You are a scam detector. Respond with 'Scam:' or 'Not a Scam:' and a brief explanation."
        )
        human_message = HumanMessage(content=f"Analyze this: {text}")
        response = model(messages=[system_message, human_message])

        # Parse AI response
        is_scam = response.content.lower().startswith("scam:")
        return {
            "response": f"🕵️ Analysis result:\n{response.content}",
            "is_scam": is_scam
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Oops! Something went wrong while analyzing the text: {str(e)}")

# API to get recently verified tokens (RugCheck)
@app.get("/api/v1/verified_tokens/")
async def verified_tokens():
    try:
        tokens = check_verified_tokens()
        if tokens:
            return {
                "response": f"✅ Verified Tokens:\n{tokens}",
            }
        else:
            return {"response": "❌ Could not fetch verified tokens at this time. Please try again later."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan_url/")
async def scan_url(url: str = Form(...)):
    try:
        # Encode the URL for VirusTotal's database lookup
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Use an async VirusTotal client
        async with vt.Client(api_key) as client:
            try:
                # Check if the URL already exists in VirusTotal
                url_data = await client.get_object_async(f"/urls/{url_id}")

                # Extract analysis data
                times_submitted = url_data.times_submitted
                last_analysis_stats = url_data.last_analysis_stats

                return {
                    "response": f"🔍 URL found in database!\n"
                                f"Times submitted: {times_submitted}\n"
                                f"Last analysis stats:\n"
                                f"  Harmless: {last_analysis_stats['harmless']}\n"
                                f"  Malicious: {last_analysis_stats['malicious']}\n"
                                f"  Suspicious: {last_analysis_stats['suspicious']}\n"
                                f"  Undetected: {last_analysis_stats['undetected']}\n"
                                f"  Timeout: {last_analysis_stats['timeout']}\n"
                }

            except vt.error.APIError as e:
                if e.code == "NotFoundError":
                    # Submit the URL for scanning
                    submission = await client.scan_url_async(url)
                    return {
                        "response": "⚠️ URL not found in VirusTotal database. It has been submitted for scanning. Check back later for results."
                    }
                else:
                    raise HTTPException(status_code=500, detail=f"API error occurred: {e.message}")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Something went wrong while scanning the URL: {str(e)}")
 
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5000)
