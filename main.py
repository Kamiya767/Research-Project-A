from flask import Flask, request, render_template
from zapv2 import ZAPv2
import time
import joblib


spam_model = joblib.load('D:\spam_classifier.joblib')
url_model = joblib.load('D:/url_classifier.joblib')

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/spam', methods=['GET', 'POST'])
def index():
    prediction = ""
    if request.method == 'POST':
        email_text = request.form['email']
        if email_text:
            prediction = spam_model.predict([email_text])[0]
            prediction = 'Spam' if prediction == 1 else 'Not Spam'
    return render_template('spam_detector.html', prediction=prediction)

@app.route('/urls', methods=['GET', 'POST'])
def urls_detector():
    prediction = ""
    if request.method == 'POST':
        url_text = request.form['url']
        if url_text:
            prediction = url_model.predict([url_text])[0]
            prediction = 'Malicious' if prediction == 0 else 'Safe'
    return render_template('urls_detector.html', prediction=prediction)


@app.route('/api-security-test', methods=['GET', 'POST'])
def api_test():
    if request.method == 'POST':
        target_url = request.form['api_url']
        zap_proxy = 'http://localhost:8080'  
        zap = ZAPv2(proxies={'http': zap_proxy, 'https': zap_proxy})

        print(f'Accessing target {target_url}')
        zap.urlopen(target_url)
        time.sleep(2)  

        print(f'Traditional Spidering target {target_url}')
        zap.spider.scan(target_url)
        while int(zap.spider.status()) < 100:
            print(f'Spider progress %: {zap.spider.status()}')
            time.sleep(5)

        print(f'Scanning target {target_url}')
        zap.ascan.scan(target_url)
        while int(zap.ascan.status()) < 100:
            print(f'Ascan progress %: {zap.ascan.status()}')
            time.sleep(5)

        alerts = zap.core.alerts(baseurl=target_url)
        return render_template('results.html', alerts=alerts, target_url=target_url)
    return render_template('api_security_test.html')

if __name__ == '__main__':
    app.run(debug=True)