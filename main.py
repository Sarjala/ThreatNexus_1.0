from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests
import shutil
import os
import time

app = FastAPI()

# Alustetaan templatet ja static-hakemisto
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# API-avaimet tähän
VIRUSTOTAL_API_KEY = "your_key_here"
ANYRUN_API_KEY = "your_key_here"
ABUSEIPDB_API_KEY = "your_key_here"
URLSCAN_API_KEY = "your_key_here"

@app.get("/", response_class=HTMLResponse) # Haetaan index-sivusto
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze-file", response_class=HTMLResponse)
async def analyze_file(request: Request, file: UploadFile = File(...), enable_anyrun: bool = Form(False)):
    # Tallennetaan syötetty tiedosto väliaikaisesti
    os.makedirs("temp", exist_ok=True)
    temp_file_path = f"temp/{file.filename}"
    with open(temp_file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # VirusTotal file upload
    vt_file = {"error": "VirusTotal: Error"}
    try:
        with open(temp_file_path, "rb") as f: #Avataan tiedosto ja syötetään API-avain post-pyyntöön
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            files = {"file": (file.filename, f)}
            vt_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
            analysis = vt_response.json() #Otetaan vastaus talteen

            # Kerätään vastauksena saatu ID ja syötetään se eteenpäin analyysiin
            analysis_id = analysis.get("data", {}).get("id")
            if analysis_id:
                analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                for _ in range(10):  # Yritetään max 10 kertaa ennen Timeout virhettä
                    status_response = requests.get(analysis_url, headers=headers) # Haetaan ID'n mukainen lopullinen analyysi
                    status_data = status_response.json()
                    if status_data.get("data", {}).get("attributes", {}).get("status") == "completed": # Tarkistetaan vastauksesta status ja joko yritetään uudestaan tai annetaan valmis data eteenpäin
                        vt_file = {"meta": status_data.get("meta", {}),
                                    "results": status_data.get("data", {}).get("attributes", {}).get("stats", {})}
                        print("nyt valmis data")
                        print(vt_file)
                        break
                    time.sleep(3) # Odota 3 sec ennen seuraavaa yritystä
                else:
                    vt_file = {"status": "timeout", "message": "VirusTotal analysis not ready in time."} # Timeout -virheviesti 10 yrityksen jälkeen
            else:
                vt_file = analysis
    except Exception as e:
        vt_file = {"error": str(e)}
        print(vt_file)

    # ANY.RUN tiedoston syöttö ja analyysin haku
    anyrun_result = {"enabled": False, "message": "ANY.RUN not enabled"} # Tieto disabloitu-tilasta
    if enable_anyrun:
        try:
            file_obj = open(temp_file_path, "rb")
            files = {
                "file": (file.filename, file_obj)}

            # Alustetaan ympäristöparametrit sandbox-ympäristölle
            multipart_data = {
                'file': (file.filename, file_obj, 'application/octet-stream'),
                'obj_type': (None, 'file'),
                'env_os': (None, 'windows'),
                'env_bitness': (None, '64'),
                'env_version': (None, '10'),
                'env_type': (None, 'complete'),
                'opt_timeout': (None, '40')
            }

            headers = {
                "Authorization": f"API-Key {ANYRUN_API_KEY}" # Haetaan API-avain
            }
            # Lähetetään post-pyyntö sisältöineen
            anyrun_response = requests.post(
                "https://api.any.run/v1/analysis/",
                headers=headers,
                files=multipart_data
            )
            submission_result = anyrun_response.json() # Otetaan talteen vastaus

            analysis_id = submission_result.get("data", {}).get("taskid") # Kerätään vastauksena saatu ID ja syötetään se eteenpäin analyysiin
            if analysis_id:
                for _ in range(20):  # Yritetään max 20 kertaa ennen Timeout virhettä
                    status_response = requests.get(f"https://api.any.run/v1/analysis/{analysis_id}", headers=headers) # Haetaan lopullinen analyysi vastauksena saadun ID'n perusteella
                    status_data = status_response.json()
                    state = status_data.get("data", {}).get("status")
                    if state == "done": # Jos analyysi on valmis, kerätään halutut tiedot raaka json-tiedostosta ja niputetaan ne yhteen
                        base = status_data.get("data", {}).get("analysis", {}).get("content", {})
                        anyrun_result = {"file": base.get("mainObject", {}).get("filename", {}),
                                            "web_result": status_data.get("data", {}).get("analysis", {}).get("permanentUrl"),
                                            "hashes": base.get("mainObject", {}).get("hashes", {}),
                                            "info": base.get("mainObject", {}).get("info", {}),
                                            "pcap_url": base.get("pcap", {}).get("permanentUrl"),
                                            "screenshots": base.get("screenshots", []),
                                            "verdict": status_data.get("data", {}).get("analysis", {}).get("scores", {}).get("verdict", {}),
                                            "counters": status_data.get("data", {}).get("counters", []),
                                            "incidents": status_data.get("data", {}).get("incidents", []),
                                            "enabled": True
                            }
                        break
                    time.sleep(3) # Odota 3 sec ennen seuraavaa yritystä
                else:
                    anyrun_result = {"status": "timeout", "message": "Analysis not ready in time."} # Timeout viesti 20 yrityksen jälkeen
            else:
                anyrun_result = submission_result
        except Exception as e:
            anyrun_result = {"error": str(e)}
        file_obj.close()

    # Poistetaan väliaikainen tiedosto
    os.remove(temp_file_path)
    # Palautetaan results-template ja syötetään siihen saadut tiedot
    return templates.TemplateResponse("result.html", {
        "request": request,
        "vt_file": vt_file,
        "anyrun_result": anyrun_result
    })
# IP- ja domain osoitteiden analysointi
@app.post("/analyze-ip", response_class=HTMLResponse)
async def analyze_ip(request: Request, ip_or_domain: str = Form(...)):
    vt_result = {"error": "VirusTotal: Error"}
    abuse_result = {"error": "AbuseIPDB: Error"}
    url_result = {"error": "URL-Scan: Error"}

    # VirusTotal IP/Domain lookup
    try:
        headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        vt_response = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_or_domain}", headers=headers)
        if vt_response.status_code not in (200, 404): #Nostetaan virhe jos ei ok tai 404
                raise Exception(vt_response.json().get("error", {}).get("message"))
        if vt_response.status_code == 404: #Jos saatu 404, yritetään toista rajapintaa
            vt_response = requests.get(f"https://www.virustotal.com/api/v3/domains/{ip_or_domain}", headers=headers)
        vt_ip_result = vt_response.json()
        vt_result = {
                    "verdict": vt_ip_result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
                    "location": vt_ip_result.get("data", {}).get("attributes", {}).get("country"),
                    "whois": vt_ip_result.get("data", {}).get("attributes", {}).get("whois")
                }
    except Exception as e:
        vt_result = {"error": str(e)}
        print(vt_result)

    # AbuseIPDB IP lookup
    try:
        if all(c.isdigit() or c == '.' for c in ip_or_domain): # Tarkistetaan onko syötetty data IP-muotoinen
            headers = {
                "Key": ABUSEIPDB_API_KEY, # Haetaan API-avain
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_or_domain,
                "maxAgeInDays": 90 # Haetaan tuloksia viimeisen 90 päivän ajalta
            }
            abuse_response = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
            if abuse_response.status_code != 200: #Nostetaan virhe jos kaikki ei ok
                errors = abuse_response.json().get("errors", [])
                raise Exception(errors[0].get("detail"))
            abuseipdb_result = abuse_response.json() #Jos ok, prosessoidaan saatu data
            abuse_result = {
                            "address": abuseipdb_result.get("data", {}).get("ipAddress", {}),
                            "public": abuseipdb_result.get("data", {}).get("isPublic", {}),
                            "confidence": abuseipdb_result.get("data", {}).get("abuseConfidenceScore", {}),
                            "location": abuseipdb_result.get("data", {}).get("countryCode", {}),
                            "domain": abuseipdb_result.get("data", {}).get("domain", {}),
                            "total_reports": abuseipdb_result.get("data", {}).get("totalReports", {})
            }
        else:
            abuse_result = {"note": "AbuseIPDB only supports IP addresses, not domain names."} # Kerrotaan käyttäjälle ettei domaineja tueta
    except Exception as e:
        abuse_result = {"error": str(e)}
        print(abuse_result) #Tulostetaan virheviesti

    #UrlScan.io lookup
    try:
        headers = {
            "api-key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "url": ip_or_domain,
        }
        url_response = requests.post("https://urlscan.io/api/v1/scan", headers=headers, json=payload)
        if url_response.status_code != 200: #Nostetaan virhe jos kaikki ei ok
            errors = url_response.json().get("errors", [])
            raise Exception(errors[0].get("detail"))
        url_json = url_response.json()
        url_id = url_json.get("uuid")
        time.sleep(5)
        for i in range(20): #Yritetään max 20 kertaa tulosten hakemista
            url_results = requests.get(f"https://urlscan.io/api/v1/result/{url_id}/", headers=headers)
            if url_results.status_code == 200: #Jos ok, prosessoidaan saatu data
                url_results_json = url_results.json()
                url_result = {
                            "ip": url_results_json.get("page", {}).get("ip"),
                            "domain": url_results_json.get("page", {}).get("domain"),
                            "score": url_results_json.get("verdicts", {}).get("overall", {}).get("score"),
                            "categories": url_results_json.get("verdicts", {}).get("overall", {}).get("categories", {}),
                            "web_result": url_results_json.get("task", {}).get("reportURL"),
                            "verdict": url_results_json.get("verdicts", {}).get("overall", {}).get("malicious"),
                            "screenshot": url_results_json.get("task", {}).get("screenshotURL")
                            }
                break
            time.sleep(2) #Odotetaan 2 sec yritysten välillä
    except Exception as e:
        url_result = {"error": str(e)}
        print(url_result) #Tulostetaan virheviesti

    # Palautetaan results-template ja syötetään siihen saadut tiedot
    return templates.TemplateResponse("result.html", {
        "request": request,
        "vt_result": vt_result,
        "abuse_result": abuse_result,
        "url_result": url_result
    })
