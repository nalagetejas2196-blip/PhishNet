from flask import Flask, request, jsonify, render_template_string
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
import pandas as pd

app = Flask(__name__)

# Train model fresh every time
data = {
    'url_length': [20, 100, 25, 150, 30, 200, 22, 180],
    'has_https': [1, 0, 1, 0, 1, 0, 1, 0],
    'has_ip': [0, 1, 0, 1, 0, 1, 0, 1],
    'num_dots': [1, 5, 2, 8, 1, 7, 2, 6],
    'label': [0, 1, 0, 1, 0, 1, 0, 1]
}
df = pd.DataFrame(data)
X = df.drop('label', axis=1)
y = df['label']
model = RandomForestClassifier()
model.fit(X, y)

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>PhishNet</title>
    <style>
        body{background:#0a0a0a;color:white;font-family:Arial;text-align:center;padding:50px;}
        h1{color:#00ff88;font-size:3em;}
        input{width:60%;padding:15px;font-size:1em;border-radius:10px;border:none;margin:20px;}
        button{padding:15px 40px;background:#00ff88;color:black;font-size:1em;border:none;border-radius:10px;cursor:pointer;font-weight:bold;}
        #result{margin-top:30px;font-size:2em;font-weight:bold;}
    </style>
</head>
<body>
    <h1>🛡️ PhishNet</h1>
    <p>Paste any URL to check if it's safe or a scam</p>
    <input type="text" id="url" placeholder="Paste URL here..."/>
    <br>
    <button onclick="checkURL()">Check Now</button>
    <div id="result"></div>
    <script>
        function checkURL(){
            const url=document.getElementById('url').value;
            fetch('/check?url='+encodeURIComponent(url))
            .then(r=>r.json())
            .then(data=>{
                const result=document.getElementById('result');
                if(data.result==='SAFE'){result.innerHTML='✅ SAFE';result.style.color='#00ff88';}
                else{result.innerHTML='🚨 PHISHING DETECTED!';result.style.color='#ff4444';}
            });
        }
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
    features = [[len(url), 1 if 'https' in url else 0, 1 if any(c.isdigit() for c in url.split('/')[0]) else 0, url.count('.')]]
    prediction = model.predict(features)[0]
    return jsonify({'result': 'SAFE' if prediction == 0 else 'PHISHING'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)