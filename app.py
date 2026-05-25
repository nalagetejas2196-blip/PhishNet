from flask import Flask, request, jsonify, render_template_string
import os
import requests
import base64

app = Flask(__name__)

VIRUSTOTAL_API_KEY = os.environ.get('VT_API_KEY', '')

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
        .tagline { color: #666; font-size: 0.95em; margin-bottom: 40px; }
        .input-box { background: #1a1a1a; border: 1px solid #333; border-radius: 12px; padding: 18px 20px; width: 100%; font-size: 1em; color: white; outline: none; margin-bottom: 15px; }
        .input-box:focus { border-color: #00ff88; }
        .btn { background: #00ff88; color: #000; border: none; padding: 16px 50px; border-radius: 12px; font-size: 1em; font-weight: 700; cursor: pointer; width: 100%; letter-spacing: 0.5px; margin-bottom: 10px; }
        .btn:hover { background: #00dd77; }
        .btn-google { background: white; color: #333; display: flex; align-items: center; justify-content: center; gap: 10px; }
        .btn-google:hover { background: #f5f5f5; }
        .btn-logout { background: #333; color: white; margin-top: 10px; }
        .btn-logout:hover { background: #444; }
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
        .stat { text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: 800; color: #00ff88; }
        .stat-label { color: #666; font-size: 0.75em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">PhishNet</div>
        <div class="tagline">AI-powered phishing and malware URL detector</div>

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

        <input class="input-box" type="text" id="url" placeholder="Paste any URL to check..." />
        <button class="btn" onclick="checkURL()">Check Now</button>
        <div id="scanning" class="scanning" style="display:none">Scanning across 70+ security engines...</div>
        <div class="result-box" id="resultBox">
            <div class="status" id="status"></div>
            <div class="score-number" id="scoreNum"></div>
            <div class="score-label">Risk Score out of 100</div>
            <div class="score-bar-container">
                <div class="score-bar" id="scoreBar"></div>
            </div>
            <div class="engines" id="engines"></div>
        </div>
        <div id="history" style="margin-top:30px;text-align:left;"></div>
        <div class="powered">Powered by VirusTotal Threat Intelligence</div>
    </div>

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
                const defanged = h.url.replace('http://', 'hxxp://').replace('https://', 'hxxps://');
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

            // URL Validation
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
            scoreNum.textContent = score + '/100';
            scoreBar.style.width = score + '%';

            if(score === 0){
                status.textContent = 'SAFE';
                status.className = 'status safe';
                scoreBar.style.background = '#00ff88';
                scoreNum.className = 'score-number safe';
            } else if(score <= 20){
                status.textContent = 'SUSPICIOUS';
                status.className = 'status suspicious';
                scoreBar.style.background = '#ffaa00';
                scoreNum.className = 'score-number suspicious';
            } else {
                status.textContent = 'PHISHING DETECTED';
                status.className = 'status danger';
                scoreBar.style.background = '#ff4444';
                scoreNum.className = 'score-number danger';
            }

            engines.innerHTML = data.total + ' security engines scanned &bull; ' + data.malicious + ' flagged this URL';

            if(currentUser) {
                const result = score === 0 ? 'SAFE' : score <= 20 ? 'SUSPICIOUS' : 'PHISHING';
                await addDoc(collection(db, 'scans'), {
                    uid: currentUser.uid,
                    email: currentUser.email,
                    url: url,
                    result: result,
                    score: score,
                    malicious: data.malicious,
                    total: data.total,
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
            if malicious == 0:
                result = 'SAFE'
            elif malicious <= 2:
                result = 'SUSPICIOUS'
            else:
                result = 'PHISHING'
            return jsonify({'result': result, 'malicious': malicious, 'total': total})
    except:
        pass
    features = [[len(url), 1 if 'https' in url else 0,
                 1 if any(c.isdigit() for c in url.split('/')[0]) else 0,
                 url.count('.')]]
    from sklearn.ensemble import RandomForestClassifier
    import pandas as pd
    data = {
        'url_length': [20,100,25,150,30,200,22,180,15,120,28,160,35,190,18,170,24,140,32,210],
        'has_https': [1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0],
        'has_ip': [0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1],
        'num_dots': [1,5,2,8,1,7,2,6,1,9,2,7,1,8,2,6,1,7,2,9],
        'label': [0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1,0,1]
    }
    df = pd.DataFrame(data)
    model = RandomForestClassifier()
    model.fit(df.drop('label',axis=1), df['label'])
    prediction = model.predict(features)[0]
    return jsonify({'result': 'SAFE' if prediction==0 else 'PHISHING', 'malicious': 0, 'total': 0})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)