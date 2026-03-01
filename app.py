from flask import Flask, render_template, request, redirect, session, jsonify, flash, url_for
import sqlite3
from datetime import timedelta
import time

app = Flask(__name__)
app.secret_key = "ctfsecret"


app.permanent_session_lifetime = timedelta(minutes=15)

def db():
    return sqlite3.connect("Krisha.db")

@app.context_processor
def inject_globals():
    user_data = None
    solved_count = 0
    total_challenges = 0
    if "user" in session:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT username, score FROM users WHERE id=?", (session["user"],))
        user_data = cur.fetchone()
        
        cur.execute("SELECT COUNT(DISTINCT challenge_id) FROM submissions WHERE user_id=? AND correct=1", (session["user"],))
        solved_count = cur.fetchone()[0] or 0
        
        cur.execute("SELECT COUNT(*) FROM challenges")
        total_challenges = cur.fetchone()[0] or 4
        
        con.close()
    
    return {
        'site_name': 'CTF Platform',
        'year': time.localtime().tm_year,
        'username': user_data[0] if user_data else None,
        'user_score': user_data[1] if user_data else 0,
        'solved_count': solved_count,
        'total_challenges': total_challenges,
        'comp_start': session.get('comp_start')
    }

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute(
            "SELECT id, username FROM users WHERE username=? AND password=?",
            (u, p)
        )
        user = cur.fetchone()
        con.close()

        if user:
            session.permanent = True
            session["user"] = user[0]
            session["username"] = user[1]
            return redirect(url_for('landing'))
        else:
            flash("Invalid username or password.", "error")

    return render_template("login.html")

@app.route("/instructions", methods=["GET", "POST"])
def landing():
    if "user" not in session:
        return redirect(url_for('login'))
    
    if request.method == "POST":
        session["instructions_viewed"] = True
        session["comp_start"] = int(time.time() * 1000) # Store in milliseconds for JS
        return redirect(url_for('dashboard'))

    return render_template("landing.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        con = db()
        cur = con.cursor()
        cur.execute("SELECT id FROM users WHERE username=?", (u,))
        if cur.fetchone():
            con.close()
            flash("Username already registered.", "error")
            return render_template("register.html")

        cur.execute(
            "INSERT INTO users (username, password, score) VALUES (?, ?, 0)",
            (u, p)
        )
        con.commit()
        con.close()
        flash(f"User '{u}' Registered Successfully! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template("register.html")
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for('login'))
    
    # Enforce viewing instructions/landing page first
    if not session.get("instructions_viewed"):
        return redirect(url_for('landing'))

    con = db()
    cur = con.cursor()
    
    # Fetch challenges with user's specific solve status and time (unique per challenge)
    cur.execute("""
        SELECT c.id, c.title, c.description, c.flag, c.points, c.level, 
               MAX(s.correct), MIN(s.solve_time)
        FROM challenges c
        LEFT JOIN submissions s ON c.id = s.challenge_id AND s.user_id = ? AND s.correct = 1
        GROUP BY c.id
    """, (session["user"],))
    challenges = cur.fetchall()
    con.close()

    return render_template("dashboard.html", challenges=challenges)

@app.route("/challenge/<int:cid>", methods=["GET", "POST"])
def challenge(cid):
    if "user" not in session:
        return redirect(url_for('login'))
    
    if not session.get("instructions_viewed"):
        return redirect(url_for('landing'))

    con = db()
    cur = con.cursor()

    cur.execute("SELECT * FROM challenges WHERE id=?", (cid,))
    ch = cur.fetchone()

    if not ch:
        con.close()
        return "Challenge not found", 404

    if f"start_{cid}" not in session:
        session[f"start_{cid}"] = time.time()

    cur.execute("""
        SELECT solve_time FROM submissions
        WHERE user_id=? AND challenge_id=? AND correct=1
    """, (session["user"], cid))
    solved_row = cur.fetchone()
    solved = solved_row is not None

    msg = ""
    suspicious = False
    solve_time = solved_row[0] if solved else None
    ciphertext = None 

  
    if cid == 1:
      
        pass

    xss_content = None
    if cid == 2:
        if request.method == "POST" and request.form.get('comment'):
            comment = request.form.get('comment')
            xss_content = comment 

            if "<script>" in comment.lower():
                msg = f"XSS Successful! The flag is: {ch[3]}"
            else:
                msg = "Comment posted. (Try injecting a script tag!)"

    if cid == 3:
        if request.method == "POST" and request.form.get('buffer_input'):
            buf_input = request.form.get('buffer_input')


            if len(buf_input) > 32:
                 msg = "Segmentation Fault! (You crashed the program, but too hard)"
            elif len(buf_input) > 16:
                 msg = f"Buffer Overflow Successful! You overwrote the return pointer. Flag: {ch[3]}"
            else:
                 msg = f"Buffer normal. {len(buf_input)}/16 bytes used. No overflow."
    if cid == 4:
        import random, string
        if f"crypto_flag_{cid}" not in session:
         
            plaintext = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            session[f"crypto_flag_{cid}"] = plaintext
         
            shifted = ""
            for char in plaintext:
                if char.isalpha():
                    shifted += chr((ord(char) - 65 + 3) % 26 + 65)
                else:
                    shifted += char
            session[f"crypto_cipher_{cid}"] = shifted

        ciphertext = session.get(f"crypto_cipher_{cid}")


    if request.method == "POST":

        if request.form.get("email"):
            suspicious = True
            msg = "Bot detected."
            con.close()
            return render_template(
                "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext
            )

        if cid == 1 and request.form.get('admin_user'):
            u = request.form.get('admin_user')
            p = request.form.get('admin_pass')
           
            check_val = (u + p).upper()
            if "'" in u or "'" in p or '"' in u or '"' in p or " OR " in check_val or "=" in u or "=" in p:
                 flag = ch[3]
                 msg = f"Logged in as Admin! The flag is: {flag}"
               
            else:
                 msg = "Invalid credentials. Try harder."

            con.close()
            return render_template(
                "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=False, ciphertext=ciphertext, xss_content=locals().get('xss_content')
            )

        if "flag" in request.form:
            flag = request.form.get("flag", "").strip()
            used_ai = request.form.get("used_ai") == "yes"

            start_time = session.get(f"start_{cid}", time.time())
            solve_time = round(time.time() - start_time, 2)

            if solve_time < 0: 
                suspicious = True
                msg = "Suspicious activity: solved too fast. CAPTCHA required."
                con.close()
                return render_template(
                    "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext, xss_content=locals().get('xss_content')
                )

            attempts = session.get(f"attempts_{cid}", 0) + 1
            session[f"attempts_{cid}"] = attempts

            if request.form.get("captcha") is not None:
                if request.form.get("captcha") != "7":
                    msg = "CAPTCHA failed."
                    con.close()
                    return render_template(
                        "challenge.html", ch=ch, msg=msg, solved=solved, suspicious=True, ciphertext=ciphertext, xss_content=locals().get('xss_content')
                    )

            correct_flag = ch[3]

            if cid == 4:
             
                correct_flag = f"CTF{{{session.get(f'crypto_flag_{cid}')}}}"

            if flag == correct_flag:
                # Always record a successful submission row
                cur.execute("""
                    INSERT INTO submissions 
                    (user_id, challenge_id, correct, solve_time, attempts)
                    VALUES (?, ?, 1, ?, ?)
                """, (session["user"], cid, solve_time, attempts))
                
                # Reset session attempts for this challenge for next solve cycle
                session[f"attempts_{cid}"] = 0
                
                # Only award points and original solve message if it's the first time
                if not solved:
                    cur.execute("""
                        UPDATE users SET score = score + ?
                        WHERE id = ?
                    """, (ch[4], session["user"]))
                    msg = f"Congratulations! Correct flag. +{ch[4]} points."
                else:
                    msg = "Correct flag! Participation re-recorded (Practice Mode)."
                
                con.commit()
            else:
                msg = "Invalid flag. Try again."

    con.close()
    return render_template(
        "challenge.html",
        ch=ch,
        msg=msg,
        solved=solved,
        solve_time=solve_time,
        suspicious=suspicious,
        ciphertext=ciphertext,
        xss_content=locals().get('xss_content')
    )


@app.route("/scoreboard")
def scoreboard():
    if "user" not in session:
        return redirect("/")

    con = db()
    cur = con.cursor()

    cur.execute("""
        SELECT u.username, u.score, ROUND(COALESCE(SUM(s.solve_time), 0), 2) as total_time
        FROM users u
        LEFT JOIN submissions s ON u.id = s.user_id AND s.correct = 1
        GROUP BY u.id, u.username, u.score
        ORDER BY u.score DESC, total_time ASC
    """)
    users = cur.fetchall()
    con.close()

    return render_template("scoreboard.html", users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/api/ai_helper", methods=["POST"])
def api_ai_helper():
    data = request.get_json(force=True) or {}
    question = (data.get('question') or '').strip()
    ctx = data.get('context') or {}
    ch_id = ctx.get('challenge_id')
    ch_name = ctx.get('challenge_name')
    ciphertext = ctx.get('ciphertext')

    # Rate limiting (increased slightly for better UX)
    session_key = 'ai_helper_count'
    count = session.get(session_key, 0)
    if count > 200:
        return jsonify({'answer': '🚀 Whoa there, speedy! My neural circuits need a break. Rate limit reached.'}), 429
    session[session_key] = count + 1

    q_lower = question.lower()
    # Ensure ch_id is handled as an integer for database and session lookups
    try:
        ch_id = int(ch_id) if ch_id is not None else None
    except (ValueError, TypeError):
        ch_id = None

    ch_info = None
    if ch_id:
        con = db()
        cur = con.cursor()
        cur.execute("SELECT * FROM challenges WHERE id=?", (ch_id,))
        ch_info = cur.fetchone()
        con.close()

    # Topic mapping with synonyms
    topics = {
        'sqli': ['sql', 'injection', 'sqli', 'login', 'admin', 'bypass', 'database', 'query', "' or 1=1"],
        'xss': ['xss', 'script', 'inject', 'comment', 'alert', 'javascript', 'cross-site', 'tags'],
        'buffer': ['buffer', 'overflow', 'bof', 'memory', 'crash', 'pointer', 'segmentation', 'stack', 'shellcode'],
        'crypto': ['crypto', 'caesar', 'cipher', 'shift', 'decode', 'encode', 'secret', 'classic', 'alphabet'],
    }

    # Identify topic
    current_topic = None
    for topic, keywords in topics.items():
        if any(k in q_lower for k in keywords):
            current_topic = topic
            break
    
    # Fallback to current challenge type if no specific topic mentioned
    if not current_topic and ch_name:
        if "sql" in ch_name.lower(): current_topic = 'sqli'
        elif "xss" in ch_name.lower(): current_topic = 'xss'
        elif "buffer" in ch_name.lower(): current_topic = 'buffer'
        elif "crypto" in ch_name.lower(): current_topic = 'crypto'

    # Define knowledge base with dynamic components
    kb = {
        'sqli': {
            "title": "SQL Injection (SQLi)",
            "concept": "SQLi occurs when user input is concatenated into SQL queries. Using ' OR 1=1-- creates a tautology that bypasses password checks.",
            "hint": "Try the payload ' OR 1=1-- in the login field.",
            "payload": "' OR 1=1--"
        },
        'xss': {
            "title": "Cross-Site Scripting (XSS)",
            "concept": "XSS allows you to inject malicious scripts into web pages. In this case, the comment field is not sanitized.",
            "hint": "Inject a script tag like <script>alert('xss')</script> to reveal the flag.",
            "payload": "<script>alert('xss')</script>"
        },
        'buffer': {
            "title": "Buffer Overflow (BoF)",
            "concept": "A buffer overflow overwrites memory when input exceeds the allocated space. This lets you control the execution flow.",
            "hint": "The buffer is 16 bytes. Send 17 characters to overflow it.",
            "payload": "AAAAAAAAAAAAAAAAA"
        },
        'crypto': {
            "title": "Caesar Cipher (Cryptography)",
            "concept": "This challenge uses a Caesar Shift of +3. To decrypt it, shift each letter back by 3.",
            "hint": f"The ciphertext is '{ciphertext}'. Shift it back by 3 to find the flag.",
            "payload": "Shift each character back by 3."
        }
    }

    # Responses
    prefix = random.choice([
        "Analysis complete. ",
        "Greetings. Here are the results: ",
        "Deep Dive initiated. Findings: ",
        "Neural Link active. Technical brief: "
    ])

    practice_notice = "\n\n> Note: Using AI hints will mark this solve as Practice Mode (0 points)."
    
    # Check if they are greeting
    if any(w in q_lower for w in ['hi', 'hello', 'hey', 'start', 'greet']):
         return jsonify({'answer': f"{prefix}\n\nI am your CTF Assistant. I can explain vulnerabilities or provide exact payloads and flags for SQLi, XSS, Buffer Overflow, and Crypto challenges.\n\nHow can I help?"})

    # Check if they want the flag/payload
    wants_solution = any(w in q_lower for w in ['flag', 'payload', 'exactly', 'solution', 'how to solve', 'give me the answer', 'cheat', 'ans'])

    if current_topic in kb:
        item = kb[current_topic]
        if wants_solution:
            # Get the real flag from DB/Session
            real_flag = ch_info[3] if ch_info else "CTF{flag_not_found}"
            
            if current_topic == 'crypto':
                # Handle dynamic crypto flag from session
                crypto_key = f"crypto_flag_{ch_id}"
                crypto_flag = session.get(crypto_key)
                if crypto_flag:
                    real_flag = f"CTF{{{crypto_flag}}}"
                    item['payload'] = f"The shift is +3. Plaintext: {crypto_flag}"
                else:
                    # In case session is lost but ch_info exists
                    if ch_info: real_flag = ch_info[3]
            
            return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### Solution for {item['title']}\n"
                f"To solve this immediately, use these details:\n\n"
                f"**Payload:** ` {item['payload']} `\n"
                f"**Flag:** `{real_flag}`\n\n"
                f"**Why it works:** {item['concept']}"
                f"{practice_notice}"
            )})
        else:
            return jsonify({'answer': (
                f"{prefix}\n\n"
                f"### Information: {item['title']}\n"
                f"**Concept:** {item['concept']}\n"
                f"**Hint:** {item['hint']}\n\n"
                f"Ask for the 'solution' or 'flag' for a technical payload."
            )})

    # Fallback
    return jsonify({'answer': (
        f"I am ready to help, but I need to know which challenge you are working on.\n\n"
        f"I can provide perfect answers for:\n"
        f"- SQL Injection\n"
        f"- XSS Attacks\n"
        f"- Buffer Overflows\n"
        f"- Crypto Challenges\n\n"
        f"Just ask for a 'hint' or the 'solution' for any of these."
    )})
import random



@app.route("/exit_portal")
def exit_portal():
    if "user" not in session:
        return redirect(url_for('login'))
    return render_template("exit_portal.html")

# Webview API for lockdown functions
class Api:
    def close_app(self):
        import os
        os._exit(0)
    
    def minimize_app(self):
        if 'window' in globals():
            globals()['window'].minimize()




@app.route("/api/increment_tab_switch", methods=["POST"])
def increment_tab_switch():
    if "user" not in session:
        return jsonify({"success": False}), 403
    
    con = db()
    cur = con.cursor()
    cur.execute("UPDATE users SET tab_switches = tab_switches + 1 WHERE id = ?", (session["user"],))
    con.commit()
    con.close()
    return jsonify({"success": True})

@app.route("/report")
def report():
    if "user" not in session:
        return redirect("/")
    
    con = db()
    cur = con.cursor()
    cur.execute("SELECT username, score, tab_switches FROM users WHERE id=?", (session["user"],))
    user_stats = cur.fetchone()
    
    cur.execute("""
        SELECT c.title, MIN(s.solve_time), COUNT(s.id)
        FROM submissions s
        JOIN challenges c ON s.challenge_id = c.id
        WHERE s.user_id = ? AND s.correct = 1
        GROUP BY c.id
    """, (session["user"],))
    solved_challenges = cur.fetchall()
    con.close()
    
    return render_template("report.html", user_stats=user_stats, solved_challenges=solved_challenges)

def start_server():
    app.run(port=5000, debug=False, use_reloader=False)

if __name__ == "__main__":
    import threading
    try:
        import webview
        
        # Start Flask Server in background thread
        t = threading.Thread(target=start_server)
        t.daemon = True
        t.start()
        
        # Create Fullscreen Lockdown Window
        api = Api()
        global window
        window = webview.create_window(
            "CTF Lockdown Browser",
            "http://localhost:5000",
            fullscreen=True,
            js_api=api
        )
        webview.start()
    except ImportError:
        print("pywebview not installed. Running in standard web mode...")
        app.run(debug=True)
