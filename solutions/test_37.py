import subprocess
import srp
import srp.srp_client
import time
import os

def test_37():
    cmd = "flask run --reload -h 0.0.0.0 -p 8000"
    env = os.environ.copy()
    env['FLASK_APP'] = './srp/srp_server.py'
    p = subprocess.Popen(cmd.split(' '), env=env)
    try:
        time.sleep(3)
        assert srp.srp_client.login(password=b'Iliketurtles1') == False
        assert srp.srp_client.login(password=b'Iliketurtles1!') == True
    except Exception as e:
        print(e)
        p.terminate()
        assert True == False