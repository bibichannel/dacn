from flask import Flask, render_template
from handles_honeypot import create_honeypots, stop_honeypots, info_honeypots

app = Flask(__name__)

@app.route('/create_honeypot/<number>')
def create_c(number):
    message = ""
    for key, value in create_honeypots(int(number)).items():
        message += f"{key} - ipadress: {value} | "
    return render_template('index.html', data=message)

@app.route('/stop_honeypots/<number>')
def delete_c(number):
    message = ""
    for key, value in stop_honeypots(int(number)).items():
        message += f"{key} - ipadress: {value} | "
    return render_template('index.html', data=message)

@app.route('/info_honeypots')
def infomation_c():
    info_honeypots()
    data = info_honeypots()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run(port=15091)