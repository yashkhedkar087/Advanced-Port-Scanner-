from flask import Flask, request, render_template
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        target = request.form['target']
        result = subprocess.run(['python', 'port_scanner.py', target], capture_output=True, text=True)
        return render_template('index.html', output=result.stdout)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
