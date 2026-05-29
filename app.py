from flask import Flask, request, jsonify, render_template_string
import os
import requests
import base64
import re
import pickle
import numpy as np
from feature_extractor import extract_features

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY', '')
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY', '')

# Load trained ML model
with open('model.pkl', 'rb') as f:
    ml_model = pickle.load(f)

SCAM_KEYWORDS = [
    'pay now', 'urgent', 'winner', 'won', 'prize', 'lottery', 'free money',
    'click here', 'verify account', 'suspended', 'blocked', 'otp',
    'registration fee', 'pay fee', 'selected for internship', 'job offer',
    'work from home', 'earn money', 'congratulations', 'you have been selected',
    'claim now', 'kyc update', 'upi', 'send money', 'transfer money',
    'bitcoin', 'crypto', 'double your money', 'guaranteed returns'
]

def extract_urls(text):
    pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(pattern, text)

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers=headers
        )
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            return malicious, total
    except:
        pass
    return 0, 0

def check_google_safe_browsing(url):
    try:
        payload = {
            "client": {"clientId": "PhishNet", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}',
            json=payload
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('matches'):
                return True
    except:
        pass
    return False

def check_ml_model(url):
    try:
        features = extract_features(url)
        prediction = ml_model.predict([features])[0]
        probability = ml_model.predict_proba([features])[0]
        return int(prediction), float(probability[1])
    except:
        return 0, 0.0
    HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PhishNet - URL Safety Checker</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0d0d0d; color: white; font-family: 'Segoe UI', Arial, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { width: 90%; max-width: 700px; text-align: center; padding: 40px 20px; }
        .logo { font-size: 2.5em; font-weight: 800; color: #00ff88; letter-spacing: -1px; margin-bottom: 5px; }
        .tagline { color: #666; font-size: 0.95em; margin-bottom: 20px; }
        .tab-bar { display: flex; gap: 10px; margin-bottom: 20px; }
        .tab { flex: 1; padding: 12px; border-radius: 10px; border: 1px solid #333; background: #1a1a1a; color: #666; cursor: pointer; font-size: 0.9em; font-weight: 600; }
        .tab.active { border-color: #00ff88; color: #00ff88; }
        .input-box { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 18px 20px; width: 100%; font-size: 1em; color: white; outline: none; margin-bottom: 15px; }
        .input-box:focus { border-color: #00ff88; }
        textarea.input-box { height: 150px; resize: vertical; font-family: inherit; }
        .btn { background: #00ff88; color: #000; border: none; padding: 16px 50px; border-radius: 12px; font-size: 1em; font-weight: 700; cursor: pointer; width: 100%; letter-spacing: 0.5px; margin-bottom: 10px; }
        .btn:hover { background: #00dd77; }
        .btn-google { background: white; color: #333; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .btn-google:hover { background: #f5f5f5; }
        .btn-logout { background: #333; color: white; margin-top: 10px; }
        .result-box { margin-top: 30px; background: #1a1a1a; border-radius: 16px; padding: 30px; display: none; }
        .status { font-size: 1.8em; font-weight: 800; margin-bottom: 20px; }
        .score-bar-container { background: #333; border-radius: 50px; height: 10px; margin: 15px 0; overflow: hidden; }
        .score-bar { height: 10px; border-radius: 50px; transition: width 1s ease; }
        .score-number { font-size: 3em; font-weight: 800; margin: 10px 0; }
        .score-label { color: #666; font-size: 0.85em; }
        .engines { margin-top: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #333; padding-top: 15px; }
        .safe { color: #00ff88; }
        .suspicious { color: #ffaa00; }
        .danger { color: #ff4444; }
        .scanning { color: #00ff88; font-size: 1em; margin-top: 20px; }
        .powered { margin-top: 30px; color: #333; font-size: 0.75em; }
        .user-info { background: #1a1a1a; border-radius: 12px; padding: 15px; margin-bottom: 20px; display: none; }
        .stats { display: flex; justify-content: space-around; margin-top: 10px; }
        .stat-number { font-size: 1.5em; font-weight: 800; color: #00ff88; }
        .stat-label { color: #666; font-size: 0.75em; }
        .google-flag { color: #ff4444; font-size: 0.85em; margin-top: 5px; }
        .ml-score { color: #00aaff; font-size: 0.85em; margin-top: 5px; }
        .keyword-tag { display: inline-block; background: #ff444422; color: #ff4444; border: 1px solid #ff4444; border-radius: 20px; padding: 4px 12px; margin: 4px; font-size: 0.8em; }
        .url-result { background: #0d0d0d; border-radius: 8px; padding: 12px; margin: 8px 0; text-align: left; }
        .message-verdict { font-size: 1.5em; font-weight: 800; margin-bottom: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">PhishNet</div>
        <div class="tagline">AI-powered phishing and malware detector</div>
        <div class="user-info" id="userInfo">
            <span id="userEmail" style="color:#00ff88;font-size:0.9em;"></span>
            <div class="stats">
                <div class="stat">
                    <div class="stat-number" id="totalScans">0</div>
                    <div class="stat-label">Total Scans</div>
                </div>
                <div class="stat">
                    <div class="stat-number" id="threatsFound" style="color:#ff4444;">0</div>
                    <div class="stat-label">Threats Found</div>
                </div>
                <div class="stat">
                    <div class="stat-number" id="safeScans">0</div>
                    <div class="stat-label">Safe URLs</div>
                </div>
            </div>
            <button class="btn btn-logout" onclick="logout()">Sign Out</button>
        </div>
        <div id="authSection">
            <button class="btn btn-google" onclick="signInWithGoogle()">
                <img src="https://www.google.com/favicon.ico" width="20"> Sign in with Google
            </button>
        </div>
        <div class="tab-bar">
            <div class="tab active" id="tab-url" onclick="switchTab('url')">URL Checker</div>
            <div class="tab" id="tab-message" onclick="switchTab('message')">Message Scanner</div>
        </div>
        <div id="url-section">
            <input class="input-box" type="text" id="url" placeholder="Paste any URL to check..." />
            <button class="btn" onclick="checkURL()">Check Now</button>
            <div id="scanning" class="scanning" style="display:none">Scanning across 70+ security engines + Google Safe Browsing + AI Model...</div>
            <div class="result-box" id="resultBox">
                <div class="status" id="status"></div>
                <div class="score-number" id="scoreNum"></div>
                <div class="score-label">Risk Score out of 100</div>
                <div class="score-bar-container">
                    <div class="score-bar" id="scoreBar"></div>
                </div>
                <div class="engines" id="engines"></div>
                <div class="google-flag" id="googleFlag"></div>
                <div class="ml-score" id="mlScore"></div>
                <div style="margin-top:10px;color:#333;font-size:0.75em;">Sources: VirusTotal + Google Safe Browsing + Custom ML Model (96.94% accuracy)</div>
            </div>
        </div>
        <div id="message-section" style="display:none">
            <textarea class="input-box" id="message" placeholder="Paste your WhatsApp message or email here..."></textarea>
            <button class="btn" onclick="checkMessage()">Scan Message</button>
            <div id="msg-scanning" class="scanning" style="display:none">Analyzing message...</div>
            <div class="result-box" id="msgResultBox">
                <div class="message-verdict" id="msgVerdict"></div>
                <div id="msgKeywords"></div>
                <div id="msgUrls"></div>
            </div>
        </div>
        <div id="history" style="margin-top:30px;text-align:left;"></div>
        <div class="powered">Powered by VirusTotal + Google Safe Browsing + Custom AI Model</div>
    </div>
'''
HTML += '''
    <script type="module">
        import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js";
        import { getAuth, GoogleAuthProvider, signInWithPopup, signOut, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js";
        import { getFirestore, collection, addDoc, query, orderBy, limit, getDocs, where, getCountFromServer } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";

        const firebaseConfig = {
            apiKey: "AIzaSyAIQj1JkEp0szjDZ0uQdE5QtYzIwxoPwKo",
            authDomain: "phishnet-828f8.firebaseapp.com",
            projectId: "phishnet-828f8",
            storageBucket: "phishnet-828f8.firebasestorage.app",
            messagingSenderId: "931810127259",
            appId: "1:931810127259:web:cd10d1c0f15a1257ce453e"
        };

        const app = initializeApp(firebaseConfig);
        const auth = getAuth(app);
        const db = getFirestore(app);
        const provider = new GoogleAuthProvider();
        let currentUser = null;

        window.switchTab = (tab) => {
            document.getElementById('url-section').style.display = tab === 'url' ? 'block' : 'none';
            document.getElementById('message-section').style.display = tab === 'message' ? 'block' : 'none';
            document.getElementById('tab-url').className = 'tab' + (tab === 'url' ? ' active' : '');
            document.getElementById('tab-message').className = 'tab' + (tab === 'message' ? ' active' : '');
        };

        window.signInWithGoogle = async () => {
            try { await signInWithPopup(auth, provider); }
            catch(e) { console.error(e); }
        };

        window.logout = async () => { await signOut(auth); };

        onAuthStateChanged(auth, async (user) => {
            currentUser = user;
            if(user) {
                document.getElementById('userInfo').style.display = 'block';
                document.getElementById('authSection').style.display = 'none';
                document.getElementById('userEmail').textContent = 'Signed in as ' + user.email;
                await loadUserStats();
                await loadHistory();
            } else {
                document.getElementById('userInfo').style.display = 'none';
                document.getElementById('authSection').style.display = 'block';
                document.getElementById('history').innerHTML = '';
            }
        });

        async function loadUserStats() {
            if(!currentUser) return;
            const q = query(collection(db, 'scans'), where('uid', '==', currentUser.uid));
            const snapshot = await getCountFromServer(q);
            const total = snapshot.data().count;
            const threatQ = query(collection(db, 'scans'), where('uid', '==', currentUser.uid), where('result', '==', 'PHISHING'));
            const threatSnap = await getCountFromServer(threatQ);
            const threats = threatSnap.data().count;
            const safeQ = query(collection(db, 'scans'), where('uid', '==', currentUser.uid), where('result', '==', 'SAFE'));
            const safeSnap = await getCountFromServer(safeQ);
            const safe = safeSnap.data().count;
            document.getElementById('totalScans').textContent = total;
            document.getElementById('threatsFound').textContent = threats;
            document.getElementById('safeScans').textContent = safe;
        }

        async function loadHistory() {
            if(!currentUser) return;
            const q = query(collection(db, 'scans'), where('uid', '==', currentUser.uid), orderBy('timestamp', 'desc'), limit(10));
            const snapshot = await getDocs(q);
            if(snapshot.empty) return;
            let html = '<div style="color:#666;font-size:0.85em;margin-bottom:10px;">Recent Scans</div>';
            snapshot.forEach(doc => {
                const h = doc.data();
                const color = h.result==='SAFE' ? '#00ff88' : h.result==='SUSPICIOUS' ? '#ffaa00' : '#ff4444';
                const defanged = h.url ? h.url.replace('http://', 'hxxp://').replace('https://', 'hxxps://') : 'Message scan';
                html += `<div style="background:#1a1a1a;border-radius:8px;padding:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;">
                    <div style="color:#aaa;font-size:0.8em;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:70%">${defanged}</div>
                    <div style="color:${color};font-size:0.8em;font-weight:700">${h.result}</div>
                </div>`;
            });
            document.getElementById('history').innerHTML = html;
        }

        window.checkURL = async () => {
            const url = document.getElementById('url').value;
            if(!url) return;
            const urlPattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
            if(!urlPattern.test(url)) {
                alert('Please enter a valid URL');
                return;
            }
            document.getElementById('resultBox').style.display = 'none';
            document.getElementById('scanning').style.display = 'block';
            const response = await fetch('/check?url=' + encodeURIComponent(url));
            const data = await response.json();
            document.getElementById('scanning').style.display = 'none';
            document.getElementById('resultBox').style.display = 'block';
            const score = data.total > 0 ? Math.round((data.malicious / data.total) * 100) : 0;
            const status = document.getElementById('status');
            const scoreNum = document.getElementById('scoreNum');
            const scoreBar = document.getElementById('scoreBar');
            const engines = document.getElementById('engines');
            const googleFlag = document.getElementById('googleFlag');
            const mlScore = document.getElementById('mlScore');
            scoreNum.textContent = score + '/100';
            scoreBar.style.width = score + '%';
            googleFlag.textContent = data.google_flagged ? 'Flagged by Google Safe Browsing' : '';
            mlScore.textContent = data.ml_prediction === 1 ? 'AI Model: Phishing detected (' + (data.ml_probability * 100).toFixed(1) + '% confidence)' : 'AI Model: Looks safe (' + ((1-data.ml_probability) * 100).toFixed(1) + '% confidence)';

            const isPhishing = score > 20 || data.google_flagged || data.ml_prediction === 1;
            const isSuspicious = score > 0 && score <= 20;

            if(isPhishing){
                status.textContent = 'PHISHING DETECTED';
                status.className = 'status danger';
                scoreBar.style.background = '#ff4444';
                scoreNum.className = 'score-number danger';
            } else if(isSuspicious){
                status.textContent = 'SUSPICIOUS';
                status.className = 'status suspicious';
                scoreBar.style.background = '#ffaa00';
                scoreNum.className = 'score-number suspicious';
            } else {
                status.textContent = 'SAFE';
                status.className = 'status safe';
                scoreBar.style.background = '#00ff88';
                scoreNum.className = 'score-number safe';
            }

            engines.innerHTML = data.total + ' security engines scanned &bull; ' + data.malicious + ' flagged this URL';

            if(currentUser) {
                const result = isPhishing ? 'PHISHING' : isSuspicious ? 'SUSPICIOUS' : 'SAFE';
                await addDoc(collection(db, 'scans'), {
                    uid: currentUser.uid,
                    email: currentUser.email,
                    url: url,
                    result: result,
                    score: score,
                    google_flagged: data.google_flagged,
                    ml_prediction: data.ml_prediction,
                    malicious: data.malicious,
                    total: data.total,
                    timestamp: new Date()
                });
                await loadUserStats();
                await loadHistory();
            }
        };

        window.checkMessage = async () => {
            const message = document.getElementById('message').value;
            if(!message) return;
            document.getElementById('msgResultBox').style.display = 'none';
            document.getElementById('msg-scanning').style.display = 'block';
            const response = await fetch('/check-message', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message: message})
            });
            const data = await response.json();
            document.getElementById('msg-scanning').style.display = 'none';
            document.getElementById('msgResultBox').style.display = 'block';
            const verdict = document.getElementById('msgVerdict');
            if(data.is_scam) {
                verdict.textContent = 'SCAM DETECTED';
                verdict.className = 'message-verdict danger';
            } else {
                verdict.textContent = 'MESSAGE LOOKS SAFE';
                verdict.className = 'message-verdict safe';
            }
            let keywordsHtml = '';
            if(data.found_keywords.length > 0) {
                keywordsHtml = '<div style="margin-top:15px;"><div style="color:#666;font-size:0.85em;margin-bottom:8px;">Suspicious Keywords Found:</div>';
                data.found_keywords.forEach(k => {
                    keywordsHtml += `<span class="keyword-tag">${k}</span>`;
                });
                keywordsHtml += '</div>';
            }
            document.getElementById('msgKeywords').innerHTML = keywordsHtml;
            let urlsHtml = '';
            if(data.urls.length > 0) {
                urlsHtml = '<div style="margin-top:15px;"><div style="color:#666;font-size:0.85em;margin-bottom:8px;">URLs Found in Message:</div>';
                data.urls.forEach(u => {
                    const color = u.safe ? '#00ff88' : '#ff4444';
                    const label = u.safe ? 'SAFE' : 'DANGEROUS';
                    const defanged = u.url.replace('http://', 'hxxp://').replace('https://', 'hxxps://');
                    urlsHtml += `<div class="url-result">
                        <div style="color:#aaa;font-size:0.8em;">${defanged}</div>
                        <div style="color:${color};font-size:0.8em;font-weight:700;margin-top:5px;">${label}</div>
                    </div>`;
                });
                urlsHtml += '</div>';
            }
            document.getElementById('msgUrls').innerHTML = urlsHtml;
            if(currentUser) {
                await addDoc(collection(db, 'scans'), {
                    uid: currentUser.uid,
                    email: currentUser.email,
                    url: null,
                    type: 'message',
                    result: data.is_scam ? 'PHISHING' : 'SAFE',
                    timestamp: new Date()
                });
                await loadUserStats();
                await loadHistory();
            }
        };
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/check')
def check():
    url = request.args.get('url', '')
    malicious, total = check_virustotal(url)
    google_flagged = check_google_safe_browsing(url)
    ml_prediction, ml_probability = check_ml_model(url)
    if malicious == 0 and not google_flagged and ml_prediction == 0:
        result = 'SAFE'
    elif malicious <= 2 and not google_flagged and ml_prediction == 0:
        result = 'SUSPICIOUS'
    else:
        result = 'PHISHING'
    return jsonify({
        'result': result,
        'malicious': malicious,
        'total': total,
        'google_flagged': google_flagged,
        'ml_prediction': ml_prediction,
        'ml_probability': ml_probability
    })

@app.route('/check-message', methods=['POST'])
def check_message():
    data = request.get_json()
    message = data.get('message', '').lower()
    found_keywords = [k for k in SCAM_KEYWORDS if k in message]
    urls = extract_urls(data.get('message', ''))
    url_results = []
    for url in urls:
        malicious, total = check_virustotal(url)
        google_flagged = check_google_safe_browsing(url)
        ml_prediction, _ = check_ml_model(url)
        is_safe = malicious == 0 and not google_flagged and ml_prediction == 0
        url_results.append({'url': url, 'safe': is_safe})
    dangerous_urls = [u for u in url_results if not u['safe']]
    is_scam = len(found_keywords) >= 2 or len(dangerous_urls) > 0
    return jsonify({
        'is_scam': is_scam,
        'found_keywords': found_keywords,
        'urls': url_results
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
    