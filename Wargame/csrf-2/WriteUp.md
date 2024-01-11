# csrf-2

### Overview

[Link (csrf-2)](https://dreamhack.io/wargame/challenges/269)

**Environment**
```
Language: Python
Framework: Flask, Selenium
```


1. Code Analysis<a href="#1-code-analysis"><sup>[1]</sup></a>
    - app.py
        - `users`
        - `read_url`
        - `check_csrf`
        - `/`
        - `/vuln`
        - `/flag`
        - `/login`
        - `/change_password`
2. Vulnerability<a href="#2-vunerability"><sup>[2]</sup></a>

    - CSRF(Cross Site Request Forgery)

3. Scenario<a href="#3-scenario"><sup>[3]</sup></a>

4. Payload<a href="#4-payload"><sup>[4]</sup></a>

5. Exploit<a href="#5-exploit"><sup>[5]</sup></a>

6. Conclusion<a href="#5-conclusion"><sup>[6]</sup></a>

---

### 1. Code Analysis

- app.py

    - `users`
    ```python
    users = {
        'guest': 'guest',
        'admin': FLAG
    }
    ```
    유저 정보를 `dictionary` 형태로 저장하고 있다.  
    `admin`이 `FLAG`값을 가지고 있다.

    </br>
    
    - `read_url`
    ```python
    def read_url(url, cookie={"name": "name", "value": "value"}):
        cookie.update({"domain": "127.0.0.1"})
        try:
            service = Service(executable_path="/chromedriver")
            options = webdriver.ChromeOptions()
            for _ in [
                "headless",
                "window-size=1920x1080",
                "disable-gpu",
                "no-sandbox",
                "disable-dev-shm-usage",
            ]:
            options.add_argument(_)
            driver = webdriver.Chrome(service=service, options=options)
            driver.implicitly_wait(3)
            driver.set_page_load_timeout(3)
            driver.get("http://127.0.0.1:8000/")
            driver.add_cookie(cookie)
            driver.get(url)
        except Exception as e:
            driver.quit()
            print(str(e))
            # return str(e)
            return False
        driver.quit()
        return True
    ```
    `selenium`을 이용하여 Victim의 동작을 정의하고 있다.  
    `url` 접근에 성공 여부가 `return`값으로, `boolean` 타입이다.
    
    </br>
    
    - `check_csrf`
    ```python
    def check_csrf(param, cookie={"name": "name", "value": "value"}):
        url = f"http://127.0.0.1:8000/vuln?param={urllib.parse.quote(param)}"
        return read_url(url, cookie)
    ```
    전달된 요청이 타인의 권한으로 수행되는지 확인하는 함수이다.  
    `param`과 `cookie`를 받아온다.  
    `url`에 `param`값을 붙여 `cookie`와 함께 `read_url`로 전달한다.  
    `return`값은 `read_url`과 같다.

    </br>
    
    - `/`
    ```python
    @app.route("/")
    def index():
        session_id = request.cookies.get('sessionid', None)
        try:
            username = session_storage[session_id]
        except KeyError:
            return render_template('index.html', text='please login')

        return render_template('index.html', text=f'Hello {username}, {"flag is " + FLAG if username == "admin" else "you are not an admin"}')
    ```
    `sessionid`가 존재한다면 그 값을 받아 저장되어 있는 값이라면 `username`을 특정한다.  
    `KeyError` 예외 처리로 `please login`을 출력한다.  
    `session_storage`를 통해 접근 가능한 값이 있다면 해당 값을 출력해준다.  
    이 때, `admin`이라면 `Flag`값을 함께 출력해준다.

    </br>
    
    - `/vuln`
    ```python
    @app.route("/vuln")
    def vuln():
        param = request.args.get("param", "").lower()
        xss_filter = ["frame", "script", "on"]
        for _ in xss_filter:
            param = param.replace(_, "*")
        return param
    ```
    파라미터인 `param`을 받아 변수인 `param`에 소문자로 입력받는다.  
    `xss_filter`는 `CSRF` 취약점을 공략하기 위한 문제로 추가된 값으로 예상된다.  
    리스트 내 3가지 입력에 대해 순차적으로 `*`로 치환한다.
    `param`을 그대로 `return`하기에 취약점이 존재한다.

    </br>
    
    - `/flag`
    ```python
    @app.route("/flag", methods=["GET", "POST"])
    def flag():
        if request.method == "GET":
            return render_template("flag.html")
        elif request.method == "POST":
            param = request.form.get("param", "")
            session_id = os.urandom(16).hex()
            session_storage[session_id] = 'admin'
            if not check_csrf(param, {"name":"sessionid", "value": session_id}):
                return '<script>alert("wrong??");history.go(-1);</script>'

            return '<script>alert("good");history.go(-1);</script>'
    ```
    `flag` 페이지는 `vuln` 페이지로 `POST` 요청을 할 수 있게 만들어졌다.  
    Payload를 입력하여 취약점을 공략할 페이지.
    `POST` 형식의 `request`가 이루어지면 파라미터인 `param`을 받아 변수인 `param`에 입력한다.  
    `session_id`를 16진수 16자리 난수로 생성하여 해당 세션을 `admin`으로 저장한다.  
    이후 `check_csrf`를 수행하여 성공 여부에 따라 다른 `alert` 이벤트가 발생한다.

    </br>
    
    - `/login`
    ```python
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            try:
                pw = users[username]
            except:
                return '<script>alert("not found user");history.go(-1);</script>'
            if pw == password:
                resp = make_response(redirect(url_for('index')) )
                session_id = os.urandom(8).hex()
                session_storage[session_id] = username
                resp.set_cookie('sessionid', session_id)
                return resp 
            return '<script>alert("wrong password");history.go(-1);</script>'
    ```
    `username`과 `password`를 받아 인증 절차를 진행한다.  
    여기서 `username`과 `password`는 각각 `users`의 `key`와 `value`이다.

    </br>
    
    - `/change_password`
    ```python
    @app.route("/change_password")
    def change_password():
        pw = request.args.get("pw", "")
        session_id = request.cookies.get('sessionid', None)
        try:
            username = session_storage[session_id]
        except KeyError:
            return render_template('index.html', text='please login')

        users[username] = pw
        return 'Done'
    ```
    드러나있지 않은 페이지로 인터페이스도 따로 존재하지 않는다.  
    따라서 URL로 접근하여 `pw`와 `sessionid`를 파라미터로 전달하여 이후 동작을 수행한다.  
    이후 동작으로는 `username`이 `session`값과 일치하면 해당 계정을 전송한 파라미터 `pw`로 비밀번호를 바꾼다.  
    이를 통해 `CSRF`를 이용하여 `Selenium`봇(`admin`)이 비밀번호를 변경하도록 유도할 것 이다.

---

### 2. Vunerability
- CSRF(Cross Site Request Forgery)

---

### 3. Scenario

1. 가용한 정보는 `guest`의 계정 정보와 `admin`의 `username`이다.

2. 확인된 취약점은 `CSRF`이다.

3. 공격자로의 권한으로 가능한 것이 없기에, `admin`의 권한을 취약점과 함께 이용하여 공격한다.

4. 공격은 `flag` 페이지에 Payload를 입력하여 `admin`의 접근을 유도하여 `change_password` 동작을 수행한다.

5. 변경된 비밀번호를 통해 `login`을 수행한다.

---

### 4. Payload

```html
<img src="/change_password?pw=admin">
```
접근하는 계정의 `password`를 'admin'으로 변경.

---

### 5. Exploit

1. index
![index](/Wargame/csrf-2/img/index.png)

2. vuln
![vuln](/Wargame/csrf-2/img/vuln.png)

3. flag
![flag](/Wargame/csrf-2/img/flag.png)

4. login
![login](/Wargame/csrf-2/img/login.png)

5. login - guest
![login - guest](/Wargame/csrf-2/img/login%20-%20guest.png)

6. index - guest
![index - guest](/Wargame/csrf-2/img/index%20-%20guest.png)

7. flag - payload
![flag - payload](/Wargame/csrf-2/img/flag%20-%20payload.png)

8. flag - alert
![flag - alert](/Wargame/csrf-2/img/flag%20-%20alert.png)

9. login - admin
![login - admin](/Wargame/csrf-2/img/login%20-%20admin.png)

10. index - admin
![index - admin](/Wargame/csrf-2/img/index%20-%20admin.png)

---

### 6. Conclusion



---

[_Go to top_ ↑](#csrf-2)