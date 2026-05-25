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
    <title>PhishNet</title>
    <style>
        body{background:#0a0a0a;color:white;font-family:Arial;text-align:center;padding:50px;}
        h1{color:#00ff88;font-size:3em;}
        p{color:#aaa;}
        input{width:60%;padding:15px;font-size:1em;border-radius:10px;border:none;margin:20px;}
        button{padding:15px 40px;background:#00ff88;color:black;font-size:1em;border:none;border-radius:10px;cursor:pointer;font-weight:bold;}
        #result{margin-top:30px;font-size:1.5em;font-weight:bold;}
        #details{margin-top:15px;font-size:1em;color:#aaa;}
        .loading{color:#00ff88;}
    </style>
</head>
<body>
    <h1>PhishNet</h1>
    <p>Paste any URL to check if it's safe or a scam</p>
    <input type="text" id="url" placeholder="Paste URL here..."/>
    <br>
    <button onclick="checkURL()">Check Now</button>
    <div id="result"></div>
    <div id="details"></div>
    <script>
        function checkURL(){
            const url=document.getElementById('url').value;
            if(!url){return;}
            document.getElementById('result').innerHTML='Scanning...';
            document.getElementById('result').style.color='#00ff88';
            document.getElementById('details').innerHTML='';
            fetch('/check?url='+encodeURIComponent(url))
            .then(r=>r.json())
            .then(data=>{
                const result=document.getElementById('result');
                const details=document.getElementById('details');
                if(data.result==='SAFE'){
                    result.innerHTML='SAFE';
                    result.style.color='#00ff88';
                }else if(data.result==='PHISHING'){
                    result.innerHTML='PHISHING DETECTED!';
                    result.style.color='#ff4444';
                }else{
                    result.innerHTML='SUSPICIOUS';
                    result.style.color='#ffaa00';
                }
                details.innerHTML='Engines detected: '+data.malicious+' / '+data.total;
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
    
    try:
        # Encode URL for VirusTotal
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
                
            return jsonify({
                'result': result,
                'malicious': malicious,
                'total': total
            })
    except:
        pass
    
    # Fallback to ML model
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