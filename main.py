from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
import os
import json
from datetime import datetime, timedelta
import hashlib
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = 'chatnell-secret-key-2024'

# Custom template filter for time formatting
@app.template_filter('format_time')
def format_time(timestamp):
    try:
        from datetime import datetime
        date = datetime.fromisoformat(timestamp)
        now = datetime.now()
        diffMs = (now - date).total_seconds() * 1000
        diffMins = diffMs // 60000
        diffHours = diffMs // 3600000
        diffDays = diffMs // 86400000
        
        if diffMins < 1:
            return 'Şimdi'
        if diffMins < 60:
            return f'{int(diffMins)}dk'
        if diffHours < 24:
            return f'{int(diffHours)}sa'
        if diffDays < 7:
            return f'{int(diffDays)}g'
        return date.strftime('%d.%m')
    except:
        return 'Bilinmiyor'

# Data storage files
USERS_FILE = 'users.json'
MESSAGES_FILE = 'messages.json'
FRIENDSHIPS_FILE = 'friendships.json'
REACTIONS_FILE = 'reactions.json'
SCHEDULED_MESSAGES_FILE = 'scheduled_messages.json'
POSTS_FILE = 'posts.json'
FOLLOWERS_FILE = 'followers.json'

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt', 'mp3', 'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm'}

# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('static', exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, ensure_ascii=False, indent=2)

def load_messages():
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_messages(messages):
    with open(MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(messages, f, ensure_ascii=False, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def load_friendships():
    if os.path.exists(FRIENDSHIPS_FILE):
        with open(FRIENDSHIPS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_friendships(friendships):
    with open(FRIENDSHIPS_FILE, 'w', encoding='utf-8') as f:
        json.dump(friendships, f, ensure_ascii=False, indent=2)

def load_reactions():
    if os.path.exists(REACTIONS_FILE):
        with open(REACTIONS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_reactions(reactions):
    with open(REACTIONS_FILE, 'w', encoding='utf-8') as f:
        json.dump(reactions, f, ensure_ascii=False, indent=2)

def load_scheduled_messages():
    if os.path.exists(SCHEDULED_MESSAGES_FILE):
        with open(SCHEDULED_MESSAGES_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_scheduled_messages(scheduled_messages):
    with open(SCHEDULED_MESSAGES_FILE, 'w', encoding='utf-8') as f:
        json.dump(scheduled_messages, f, ensure_ascii=False, indent=2)

def load_posts():
    if os.path.exists(POSTS_FILE):
        with open(POSTS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_posts(posts):
    with open(POSTS_FILE, 'w', encoding='utf-8') as f:
        json.dump(posts, f, ensure_ascii=False, indent=2)

def load_followers():
    if os.path.exists(FOLLOWERS_FILE):
        with open(FOLLOWERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_followers(followers):
    with open(FOLLOWERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(followers, f, ensure_ascii=False, indent=2)

def get_follower_count(username):
    followers = load_followers()
    return len(followers.get(username, []))

def get_user_friends(username):
    friendships = load_friendships()
    return friendships.get(username, {'friends': [], 'sent_requests': [], 'received_requests': []})

def load_notifications():
    try:
        if os.path.exists('notifications.json'):
            with open('notifications.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        return {}
    except:
        return {}

def save_notifications(notifications):
    try:
        with open('notifications.json', 'w', encoding='utf-8') as f:
            json.dump(notifications, f, ensure_ascii=False, indent=2)
    except:
        pass

def add_notification(username, notification):
    notifications = load_notifications()
    if username not in notifications:
        notifications[username] = []

    notifications[username].append(notification)

    # Keep only last 50 notifications per user
    if len(notifications[username]) > 50:
        notifications[username] = notifications[username][-50:]

    save_notifications(notifications)

def are_friends(user1, user2):
    user1_friends = get_user_friends(user1)
    return user2 in user1_friends['friends']

def can_send_message(sender, recipient):
    users = load_users()
    recipient_data = users.get(recipient, {})

    # Eğer alıcı herkesten mesaj almayı açtıysa herkes gönderebilir
    if recipient_data.get('allow_messages_from_all', True):
        return True

    # Kapalıysa sadece arkadaşlar gönderebilir
    return are_friends(sender, recipient)



@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    if 'guest' in session:
        return redirect(url_for('nells'))
    return render_template('index.html')

@app.route('/guest_login')
def guest_login():
    session['guest'] = True
    return redirect(url_for('nells'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        users = load_users()

        if username in users:
            flash('Kullanıcı adı zaten mevcut!')
            return render_template('register.html')

        if password != confirm_password:
            flash('Şifreler eşleşmiyor!')
            return render_template('register.html')

        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalıdır!')
            return render_template('register.html')

        users[username] = {
            'password': hash_password(password),
            'created_at': datetime.now().isoformat(),
            'profile_photo': None,
            'bio': '',
            'last_seen': datetime.now().isoformat(),
            'status': 'online',
            'allow_messages_from_all': True,
            'posts': []
        }

        save_users(users)
        flash('Kayıt başarılı! Giriş yapabilirsiniz.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        users = load_users()

        if username in users and users[username]['password'] == hash_password(password):
            session['username'] = username
            users[username]['last_seen'] = datetime.now().isoformat()
            users[username]['status'] = 'online'
            save_users(users)
            return redirect(url_for('dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre!')

    return render_template('login.html')

@app.route('/logout')
def logout():
    is_guest = 'guest' in session
    if 'username' in session:
        users = load_users()
        if session['username'] in users:
            users[session['username']]['status'] = 'offline'
            users[session['username']]['last_seen'] = datetime.now().isoformat()
            save_users(users)
    session.pop('username', None)
    session.pop('guest', None)

    # Misafir kullanıcı giriş yapmak istiyorsa login sayfasına yönlendir
    if is_guest:
        return redirect(url_for('login'))
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'guest' in session:
        return redirect(url_for('nells'))
    if 'username' not in session:
        return redirect(url_for('login'))

    users = load_users()
    user_list = [user for user in users.keys() if user != session['username']]

    return render_template('dashboard.html', users=user_list)

@app.route('/nells')
def nells():
    if 'username' not in session and 'guest' not in session:
        return redirect(url_for('index'))

    posts = load_posts()
    users = load_users()
    current_user = session.get('username', '')
    
    # Gönderileri filtrele
    filtered_posts = []
    for post in posts:
        # Eğer post public ise herkese göster
        if post.get('is_public', True):
            filtered_posts.append(post)
        # Eğer post private ise sadece arkadaşlara göster
        elif current_user and are_friends(current_user, post['username']):
            filtered_posts.append(post)
    
    # Tarihe göre ters sırala (en yeni üstte)
    filtered_posts.sort(key=lambda x: x['created_at'], reverse=True)

    # Her post için takipçi sayısını ekle
    for post in filtered_posts:
        follower_count = get_follower_count(post['username'])
        post['followers_count'] = follower_count if follower_count is not None else 0

    is_guest = 'guest' in session
    return render_template('nells.html', posts=filtered_posts, is_guest=is_guest, users_data=users)

@app.route('/chat/<recipient>')
def chat(recipient):
    if 'guest' in session:
        flash('Misafir kullanıcılar mesaj gönderemez!')
        return redirect(url_for('nells'))
    if 'username' not in session:
        return redirect(url_for('login'))
    users = load_users()

    if recipient not in users:
        flash('Kullanıcı bulunamadı!')
        return redirect(url_for('dashboard'))

    return render_template('chat.html', recipient=recipient)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    recipient = data.get('recipient')
    message = data.get('message')

    if not recipient or not message:
        return jsonify({'success': False, 'error': 'Geçersiz veri'})

    # Mesaj gönderme yetkisi kontrolü
    if not can_send_message(session['username'], recipient):
        return jsonify({'success': False, 'error': 'Bu kişiye mesaj göndermek için arkadaş olmanız gerekiyor'})

    messages = load_messages()

    new_message = {
        'id': len(messages),
        'sender': session['username'],
        'recipient': recipient,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'reactions': {}
    }

    messages.append(new_message)
    save_messages(messages)

    return jsonify({'success': True})

@app.route('/get_messages/<recipient>')
def get_messages(recipient):
    if 'username' not in session:
        return jsonify([])
    messages = load_messages()

    # Get conversation between current user and recipient
    conversation = []
    for msg in messages:
        if (msg['sender'] == session['username'] and msg['recipient'] == recipient) or \
           (msg['sender'] == recipient and msg['recipient'] == session['username']):
            conversation.append(msg)

    # Sort by timestamp
    conversation.sort(key=lambda x: x['timestamp'])

    return jsonify(conversation)

@app.route('/profile/<username>')
def profile(username):
    if 'username' not in session and 'guest' not in session:
        return redirect(url_for('index'))

    users = load_users()

    if username not in users:
        flash('Kullanıcı bulunamadı!')
        if 'guest' in session:
            return redirect(url_for('nells'))
        return redirect(url_for('dashboard'))

    user_info = users[username]
    is_own_profile = 'username' in session and username == session['username']
    is_guest = 'guest' in session

    return render_template('profile.html', 
                         profile_user=username, 
                         user_info=user_info,
                         is_own_profile=is_own_profile,
                         is_guest=is_guest)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'username' not in session:
        return redirect(url_for('login'))

    users = load_users()
    current_user = session['username']

    if request.method == 'POST':
        bio = request.form.get('bio', '')

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{current_user}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                users[current_user]['profile_photo'] = f"uploads/{filename}"

        users[current_user]['bio'] = bio
        save_users(users)
        flash('Profil başarıyla güncellendi!')
        return redirect(url_for('profile', username=current_user))

    return render_template('edit_profile.html', user_info=users[current_user])

@app.route('/delete_message', methods=['POST'])
def delete_message():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    message_id = data.get('message_id')

    if message_id is None:
        return jsonify({'success': False, 'error': 'Mesaj ID gerekli'})

    messages = load_messages()

    # Find and delete the message if user owns it
    for i, msg in enumerate(messages):
        if msg.get('id') == message_id and msg['sender'] == session['username']:
            messages[i]['deleted'] = True
            messages[i]['message'] = 'Bu mesaj silindi'
            save_messages(messages)
            return jsonify({'success': True})

    return jsonify({'success': False, 'error': 'Mesaj bulunamadı veya yetkiniz yok'})

@app.route('/search_messages')
def search_messages():
    if 'username' not in session:
        return jsonify([])

    query = request.args.get('q', '').lower()
    recipient = request.args.get('recipient', '')

    if not query or not recipient:
        return jsonify([])

    messages = load_messages()
    results = []

    for msg in messages:
        if (msg['sender'] == session['username'] and msg['recipient'] == recipient) or \
           (msg['sender'] == recipient and msg['recipient'] == session['username']):
            if query in msg['message'].lower() and not msg.get('deleted', False):
                results.append(msg)

    return jsonify(results[:10])  # Limit to 10 results

@app.route('/get_user_status/<username>')
def get_user_status(username):
    if 'username' not in session:
        return jsonify({'status': 'unknown'})

    users = load_users()
    if username in users:
        last_seen = datetime.fromisoformat(users[username].get('last_seen', datetime.now().isoformat()))
        now = datetime.now()
        minutes_ago = (now - last_seen).total_seconds() / 60

        if minutes_ago < 5:
            status = 'online'
        elif minutes_ago < 30:
            status = 'away'
        else:
            status = 'offline'

        return jsonify({
            'status': status,
            'last_seen': users[username].get('last_seen')
        })

    return jsonify({'status': 'unknown'})

@app.route('/search_users')
def search_users():
    if 'username' not in session:
        return jsonify([])

    query = request.args.get('q', '').lower()
    if len(query) < 2:
        return jsonify([])

    users = load_users()
    current_user = session['username']
    results = []

    for username, user_data in users.items():
        if username != current_user and query in username.lower():
            follower_count = get_follower_count(username)
            results.append({
                'username': username,
                'followers_count': follower_count if follower_count is not None else 0
            })

    # Limit to 10 results
    return jsonify(results[:10])

@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    if 'guest' in session:
        return jsonify({'success': False, 'error': 'Misafir kullanıcılar arkadaşlık isteği gönderemez'})
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    target_user = data.get('username')
    current_user = session['username']

    if not target_user or target_user == current_user:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    users = load_users()
    if target_user not in users:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'})

    friendships = load_friendships()

    # Mevcut arkadaşlık verilerini al
    current_user_data = friendships.get(current_user, {'friends': [], 'sent_requests': [], 'received_requests': []})
    target_user_data = friendships.get(target_user, {'friends': [], 'sent_requests': [], 'received_requests': []})

    # Zaten arkadaş mı kontrol et
    if target_user in current_user_data['friends']:
        return jsonify({'success': False, 'error': 'Zaten arkadaşsınız'})

    # Zaten istek gönderilmiş mi kontrol et
    if target_user in current_user_data['sent_requests']:
        return jsonify({'success': False, 'error': 'Zaten arkadaşlık isteği gönderilmiş'})

    # İsteği ekle
    current_user_data['sent_requests'].append(target_user)
    target_user_data['received_requests'].append(current_user)

    friendships[current_user] = current_user_data
    friendships[target_user] = target_user_data

    save_friendships(friendships)

    return jsonify({'success': True, 'message': 'Arkadaşlık isteği gönderildi'})

@app.route('/accept_friend_request', methods=['POST'])
def accept_friend_request():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    requester = data.get('username')
    current_user = session['username']

    if not requester:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    friendships = load_friendships()

    current_user_data = friendships.get(current_user, {'friends': [], 'sent_requests': [], 'received_requests': []})
    requester_data = friendships.get(requester, {'friends': [], 'sent_requests': [], 'received_requests': []})

    # İstek var mı kontrol et
    if requester not in current_user_data['received_requests']:
        return jsonify({'success': False, 'error': 'Arkadaşlık isteği bulunamadı'})

    # Arkadaş listelerine ekle
    current_user_data['friends'].append(requester)
    requester_data['friends'].append(current_user)

    # İstekleri kaldır
    current_user_data['received_requests'].remove(requester)
    requester_data['sent_requests'].remove(current_user)

    friendships[current_user] = current_user_data
    friendships[requester] = requester_data

    save_friendships(friendships)

    return jsonify({'success': True, 'message': 'Arkadaşlık isteği kabul edildi'})

@app.route('/reject_friend_request', methods=['POST'])
def reject_friend_request():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    requester = data.get('username')
    current_user = session['username']

    if not requester:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    friendships = load_friendships()

    current_user_data = friendships.get(current_user, {'friends': [], 'sent_requests': [], 'received_requests': []})
    requester_data = friendships.get(requester, {'friends': [], 'sent_requests': [], 'received_requests': []})

    # Gelen isteği reddetme (başkasından gelen istek)
    if requester in current_user_data['received_requests']:
        current_user_data['received_requests'].remove(requester)
        requester_data['sent_requests'].remove(current_user)

        friendships[current_user] = current_user_data
        friendships[requester] = requester_data
        save_friendships(friendships)

        return jsonify({'success': True, 'message': 'Arkadaşlık isteği reddedildi'})

    # Gönderilen isteği geri çekme (kendi gönderdiğin istek)
    elif requester in current_user_data['sent_requests']:
        current_user_data['sent_requests'].remove(requester)
        requester_data['received_requests'].remove(current_user)

        friendships[current_user] = current_user_data
        friendships[requester] = requester_data
        save_friendships(friendships)

        return jsonify({'success': True, 'message': 'Arkadaşlık isteği geri çekildi'})

    return jsonify({'success': False, 'error': 'Arkadaşlık isteği bulunamadı'})

@app.route('/remove_friend', methods=['POST'])
def remove_friend():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    friend_username = data.get('username')
    current_user = session['username']

    if not friend_username:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    friendships = load_friendships()

    current_user_data = friendships.get(current_user, {'friends': [], 'sent_requests': [], 'received_requests': []})
    friend_data = friendships.get(friend_username, {'friends': [], 'sent_requests': [], 'received_requests': []})

    # Arkadaş mı kontrol et
    if friend_username not in current_user_data['friends']:
        return jsonify({'success': False, 'error': 'Bu kişi arkadaş listenizde değil'})

    # Arkadaş listelerinden kaldır
    current_user_data['friends'].remove(friend_username)
    friend_data['friends'].remove(current_user)

    friendships[current_user] = current_user_data
    friendships[friend_username] = friend_data

    save_friendships(friendships)

    return jsonify({'success': True, 'message': 'Arkadaş çıkarıldı'})

@app.route('/get_user_info/<username>')
def get_user_info(username):
    users = load_users()
    if username in users:
        user_data = users[username].copy()
        # Remove sensitive data
        user_data.pop('password', None)
        return jsonify(user_data)
    return jsonify({'error': 'User not found'}), 404

@app.route('/get_friendship_data')
def get_friendship_data():
    if 'username' not in session:
        return jsonify({})

    current_user = session['username']
    user_data = get_user_friends(current_user)

    return jsonify(user_data)

@app.route('/update_message_settings', methods=['POST'])
def update_message_settings():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    allow_messages_from_all = data.get('allow_messages_from_all', True)

    users = load_users()
    users[session['username']]['allow_messages_from_all'] = allow_messages_from_all
    save_users(users)

    return jsonify({'success': True, 'message': 'Mesaj ayarları güncellendi'})

@app.route('/create_post', methods=['POST'])
def create_post():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    content = request.form.get('content', '')
    is_public = request.form.get('is_public') == 'on'

    if not content.strip():
        return jsonify({'success': False, 'error': 'İçerik boş olamaz'})

    posts = load_posts()

    new_post = {
        'id': len(posts),
        'username': session['username'],
        'content': content,
        'is_public': is_public,
        'created_at': datetime.now().isoformat(),
        'media_files': []
    }

    # Handle file uploads
    if 'media_files' in request.files:
        files = request.files.getlist('media_files')
        for file in files:
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(f"{session['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                file_type = 'video' if file.filename.lower().endswith(('mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm')) else 'image'
                new_post['media_files'].append({
                    'filename': file.filename,
                    'path': f"uploads/{filename}",
                    'type': file_type
                })

    posts.append(new_post)
    save_posts(posts)

    return jsonify({'success': True, 'message': 'Gönderi oluşturuldu'})

@app.route('/get_user_posts/<username>')
def get_user_posts(username):
    if 'username' not in session and 'guest' not in session:
        return jsonify([])

    posts = load_posts()
    user_posts = [post for post in posts if post['username'] == username]
    
    # Eğer kendi profilini görüyorsa tüm gönderileri göster
    if 'username' in session and username == session['username']:
        user_posts.sort(key=lambda x: x['created_at'], reverse=True)
        return jsonify(user_posts)
    
    # Başka birinin profilini görüyorsa
    current_user = session.get('username', '')
    
    # Arkadaşlık durumunu kontrol et
    is_friend = are_friends(current_user, username) if current_user else False
    
    # Gönderileri filtrele
    filtered_posts = []
    for post in user_posts:
        # Eğer post public ise veya arkadaşsa göster
        if post.get('is_public', True) or is_friend:
            filtered_posts.append(post)
    
    filtered_posts.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify(filtered_posts)

@app.route('/get_user_follower_count/<username>')
def get_user_follower_count(username):
    if 'username' not in session:
        return jsonify({'count': 0})

    follower_count = get_follower_count(username)
    return jsonify({'count': follower_count if follower_count is not None else 0})

@app.route('/react_to_message', methods=['POST'])
def react_to_message():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    message_id = data.get('message_id')
    reaction = data.get('reaction')

    if message_id is None or not reaction:
        return jsonify({'success': False, 'error': 'Geçersiz veri'})

    messages = load_messages()

    for msg in messages:
        if msg.get('id') == message_id:
            if 'reactions' not in msg:
                msg['reactions'] = {}

            if reaction not in msg['reactions']:
                msg['reactions'][reaction] = []

            if session['username'] in msg['reactions'][reaction]:
                msg['reactions'][reaction].remove(session['username'])
            else:
                msg['reactions'][reaction].append(session['username'])

            save_messages(messages)
            return jsonify({'success': True})

    return jsonify({'success': False, 'error': 'Mesaj bulunamadı'})

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'Dosya seçilmedi'})

    file = request.files['file']
    recipient = request.form.get('recipient')
    caption = request.form.get('caption', '')

    if file.filename == '' or not recipient:
        return jsonify({'success': False, 'error': 'Geçersiz veri'})

    if file and allowed_file(file.filename):
        filename = secure_filename(f"{session['username']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Dosya paylaşımını mesaj olarak kaydet
        messages = load_messages()
        
        # Check if it's an image file
        is_image = file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.webp'))
        
        if is_image and caption:
            message_text = caption
        else:
            message_text = f'📎 Dosya paylaştı: {file.filename}'

        new_message = {
            'id': len(messages),
            'sender': session['username'],
            'recipient': recipient,
            'message': message_text,
            'file_path': f"uploads/{filename}",
            'file_name': file.filename,
            'timestamp': datetime.now().isoformat(),
            'reactions': {},
            'is_file': True
        }

        messages.append(new_message)
        save_messages(messages)

        return jsonify({'success': True, 'file_path': f"uploads/{filename}"})

    return jsonify({'success': False, 'error': 'Desteklenmeyen dosya formatı'})

@app.route('/block_user', methods=['POST'])
def block_user():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    target_user = data.get('username')
    current_user = session['username']

    if not target_user or target_user == current_user:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    users = load_users()
    if target_user not in users:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'})

    # Load or create blocked users data
    blocked_file = 'blocked_users.json'
    if os.path.exists(blocked_file):
        with open(blocked_file, 'r', encoding='utf-8') as f:
            blocked_users = json.load(f)
    else:
        blocked_users = {}

    if current_user not in blocked_users:
        blocked_users[current_user] = []

    if target_user not in blocked_users[current_user]:
        blocked_users[current_user].append(target_user)

    with open(blocked_file, 'w', encoding='utf-8') as f:
        json.dump(blocked_users, f, ensure_ascii=False, indent=2)

    return jsonify({'success': True, 'message': 'Kullanıcı engellendi'})

@app.route('/unblock_user', methods=['POST'])
def unblock_user():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    target_user = data.get('username')
    current_user = session['username']

    if not target_user:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    blocked_file = 'blocked_users.json'
    if os.path.exists(blocked_file):
        with open(blocked_file, 'r', encoding='utf-8') as f:
            blocked_users = json.load(f)
    else:
        return jsonify({'success': False, 'error': 'Engellenmiş kullanıcı bulunamadı'})

    if current_user in blocked_users and target_user in blocked_users[current_user]:
        blocked_users[current_user].remove(target_user)

        with open(blocked_file, 'w', encoding='utf-8') as f:
            json.dump(blocked_users, f, ensure_ascii=False, indent=2)

        return jsonify({'success': True, 'message': 'Engel kaldırıldı'})

    return jsonify({'success': False, 'error': 'Kullanıcı engellenmiş değil'})

@app.route('/check_block_status/<username>')
def check_block_status(username):
    if 'username' not in session:
        return jsonify({'is_blocked': False})

    current_user = session['username']
    blocked_file = 'blocked_users.json'
    
    if os.path.exists(blocked_file):
        with open(blocked_file, 'r', encoding='utf-8') as f:
            blocked_users = json.load(f)
        
        is_blocked = current_user in blocked_users and username in blocked_users[current_user]
        return jsonify({'is_blocked': is_blocked})
    
    return jsonify({'is_blocked': False})

@app.route('/get_typing_status/<username>')
def get_typing_status(username):
    # Simple in-memory typing status - in production, you'd use Redis or similar
    typing_file = 'typing_status.json'
    if os.path.exists(typing_file):
        try:
            with open(typing_file, 'r', encoding='utf-8') as f:
                typing_data = json.load(f)
            
            user_typing = typing_data.get(username, {})
            # Check if typing status is recent (within last 3 seconds)
            if user_typing.get('timestamp'):
                last_update = datetime.fromisoformat(user_typing['timestamp'])
                if (datetime.now() - last_update).total_seconds() < 3:
                    return jsonify({'typing': user_typing.get('typing', False)})
        except:
            pass
    
    return jsonify({'typing': False})

@app.route('/update_typing_status', methods=['POST'])
def update_typing_status():
    if 'username' not in session:
        return jsonify({'success': False})

    data = request.get_json()
    typing = data.get('typing', False)
    current_user = session['username']

    typing_file = 'typing_status.json'
    if os.path.exists(typing_file):
        try:
            with open(typing_file, 'r', encoding='utf-8') as f:
                typing_data = json.load(f)
        except:
            typing_data = {}
    else:
        typing_data = {}

    typing_data[current_user] = {
        'typing': typing,
        'timestamp': datetime.now().isoformat()
    }

    try:
        with open(typing_file, 'w', encoding='utf-8') as f:
            json.dump(typing_data, f, ensure_ascii=False, indent=2)
    except:
        pass

    return jsonify({'success': True})

@app.route('/mark_messages_read', methods=['POST'])
def mark_messages_read():
    if 'username' not in session:
        return jsonify({'success': False})

    data = request.get_json()
    sender = data.get('sender')
    current_user = session['username']

    if not sender:
        return jsonify({'success': False})

    messages = load_messages()
    
    # Mark messages from sender to current user as read
    for msg in messages:
        if msg['sender'] == sender and msg['recipient'] == current_user:
            msg['read'] = True

    save_messages(messages)
    return jsonify({'success': True})

@app.route('/follow_user', methods=['POST'])
def follow_user():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    target_user = data.get('username')
    current_user = session['username']

    if not target_user or target_user == current_user:
        return jsonify({'success': False, 'error': 'Geçersiz kullanıcı'})

    users = load_users()
    if target_user not in users:
        return jsonify({'success': False, 'error': 'Kullanıcı bulunamadı'})

    followers = load_followers()
    friendships = load_friendships()

    # Takipçi listesini al
    target_followers = followers.get(target_user, [])

    # Arkadaşlık durumunu kontrol et
    current_user_friends = friendships.get(current_user, {}).get('friends', [])
    if target_user in current_user_friends:
        return jsonify({'success': False, 'error': 'Bu kişi zaten arkadaşınız'})

    # Takip durumunu kontrol et ve toggle yap
    if current_user in target_followers:
        target_followers.remove(current_user)
        message = 'İstek geri çekildi'
    else:
        target_followers.append(current_user)
        message = 'İstek gönderildi'

    followers[target_user] = target_followers
    save_followers(followers)

    return jsonify({
        'success': True, 
        'message': message,
        'follower_count': len(target_followers)
    })

@app.route('/recent_users')
def recent_users():
    if 'username' not in session:
        return jsonify([])

    users = load_users()
    current_user = session['username']

    # Kullanıcıları kayıt tarihine göre sırala ve son 4'ünü al
    user_list = []
    for username, user_data in users.items():
        if username != current_user:
            created_at = user_data.get('created_at', '')
            try:
                # Tarih formatını düzenle
                if created_at:
                    from datetime import datetime
                    date_obj = datetime.fromisoformat(created_at)
                    formatted_date = date_obj.strftime('%d.%m.%Y')
                else:
                    formatted_date = 'Bilinmiyor'
            except:
                formatted_date = 'Bilinmiyor'

            user_list.append({
                'username': username,
                'created_at': formatted_date,
                'created_at_raw': created_at
            })

    # Kayıt tarihine göre ters sırala (en yeni üstte)
    user_list.sort(key=lambda x: x.get('created_at_raw', ''), reverse=True)

    # Son 4 kullanıcıyı döndür
    return jsonify(user_list[:4])

@app.route('/all_users')
def all_users():
    if 'username' not in session:
        return redirect(url_for('login'))

    users = load_users()
    current_user = session['username']

    # Tüm kullanıcıları listele
    user_list = []
    for username, user_data in users.items():
        if username != current_user:
            created_at = user_data.get('created_at', '')
            try:
                # Tarih formatını düzenle
                if created_at:
                    from datetime import datetime
                    date_obj = datetime.fromisoformat(created_at)
                    formatted_date = date_obj.strftime('%d.%m.%Y')
                else:
                    formatted_date = 'Bilinmiyor'
            except:
                formatted_date = 'Bilinmiyor'

            user_list.append({
                'username': username,
                'created_at': formatted_date,
                'created_at_raw': created_at,
                'follower_count': get_follower_count(username) or 0
            })

    # Kayıt tarihine göre ters sırala (en yeni üstte)
    user_list.sort(key=lambda x: x.get('created_at_raw', ''), reverse=True)

    return render_template('all_users.html', users=user_list)

@app.route('/get_all_users')
def get_all_users():
    if 'username' not in session:
        return jsonify([])

    users = load_users()
    current_user = session['username']

    # Tüm kullanıcıları listele
    user_list = []
    for username, user_data in users.items():
        if username != current_user:
            created_at = user_data.get('created_at', '')
            try:
                # Tarih formatını düzenle
                if created_at:
                    from datetime import datetime
                    date_obj = datetime.fromisoformat(created_at)
                    formatted_date = date_obj.strftime('%d.%m.%Y')
                else:
                    formatted_date = 'Bilinmiyor'
            except:
                formatted_date = 'Bilinmiyor'

            user_list.append({
                'username': username,
                'created_at': formatted_date,
                'created_at_raw': created_at
            })

    # Kayıt tarihine göre ters sırala (en yeni üstte)
    user_list.sort(key=lambda x: x.get('created_at_raw', ''), reverse=True)

    return jsonify(user_list)

@app.route('/get_friend_requests')
def get_friend_requests():
    if 'username' not in session:
        return jsonify({'received_requests': []})

    current_user = session['username']
    user_data = get_user_friends(current_user)

    return jsonify({
        'received_requests': user_data.get('received_requests', [])
    })

@app.route('/delete_post', methods=['POST'])
def delete_post():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    post_id = data.get('post_id')
    current_user = session['username']

    if post_id is None:
        return jsonify({'success': False, 'error': 'Gönderi ID gerekli'})

    posts = load_posts()

    # Find and delete the post if user owns it
    for i, post in enumerate(posts):
        if post.get('id') == post_id and post.get('username') == current_user:
            # Delete associated media files
            if 'media_files' in post:
                for media_file in post['media_files']:
                    file_path = os.path.join('static', media_file['path'])
                    if os.path.exists(file_path):
                        try:
                            os.remove(file_path)
                        except:
                            pass

            # Remove post from list
            posts.pop(i)
            save_posts(posts)
            return jsonify({'success': True, 'message': 'Gönderi silindi'})

    return jsonify({'success': False, 'error': 'Gönderi bulunamadı veya yetkiniz yok'})

@app.route('/like_post', methods=['POST'])
def like_post():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    post_id = data.get('post_id')
    current_user = session['username']

    if post_id is None:
        return jsonify({'success': False, 'error': 'Gönderi ID gerekli'})

    posts = load_posts()

    # Find the post
    for post in posts:
        if post.get('id') == post_id:
            if 'likes' not in post:
                post['likes'] = []

            if current_user in post['likes']:
                # Unlike
                post['likes'].remove(current_user)
                liked = False
            else:
                # Like
                post['likes'].append(current_user)
                liked = True

                # Add notification for post owner (only when liking, not unliking)
                if post.get('username') != current_user:
                    add_notification(post.get('username'), {
                        'type': 'like',
                        'from_user': current_user,
                        'post_id': post_id,
                        'message': f'{current_user} gönderinizi beğendi',
                        'timestamp': datetime.now().isoformat()
                    })

            save_posts(posts)

            return jsonify({
                'success': True, 
                'liked': liked, 
                'like_count': len(post['likes'])
            })

    return jsonify({'success': False, 'error': 'Gönderi bulunamadı'})

@app.route('/add_comment', methods=['POST'])
def add_comment():
    if 'username' not in session:
        return jsonify({'success': False, 'error': 'Oturum açmanız gerekli'})

    data = request.get_json()
    post_id = data.get('post_id')
    comment_text = data.get('comment', '').strip()
    current_user = session['username']

    if not post_id or not comment_text:
        return jsonify({'success': False, 'error': 'Gönderi ID ve yorum gerekli'})

    posts = load_posts()

    # Find the post
    for post in posts:
        if post.get('id') == post_id:
            if 'comments' not in post:
                post['comments'] = []

            comment_id = len(post['comments'])
            new_comment = {
                'id': comment_id,
                'username': current_user,
                'comment': comment_text,
                'timestamp': datetime.now().isoformat()
            }

            post['comments'].append(new_comment)

            # Add notification for post owner (only if commenter is not the post owner)
            if post.get('username') != current_user:
                add_notification(post.get('username'), {
                    'type': 'comment',
                    'from_user': current_user,
                    'post_id': post_id,
                    'message': f'{current_user} gönderinize yorum yaptı: "{comment_text[:30]}..."',
                    'timestamp': datetime.now().isoformat()
                })

            save_posts(posts)

            return jsonify({
                'success': True,
                'comment': new_comment,
                'comment_count': len(post['comments'])
            })

    return jsonify({'success': False, 'error': 'Gönderi bulunamadı'})

@app.route('/get_post_data/<int:post_id>')
def get_post_data(post_id):
    posts = load_posts()

    for post in posts:
        if post.get('id') == post_id:
            return jsonify({
                'likes': post.get('likes', []),
                'like_count': len(post.get('likes', [])),
                'comments': post.get('comments', []),
                'comment_count': len(post.get('comments', []))
            })

    return jsonify({'error': 'Post bulunamadı'}), 404

@app.route('/get_notifications')
def get_notifications():
    if 'username' not in session:
        return jsonify([])

    username = session['username']
    notifications = load_notifications().get(username, [])

    return jsonify(notifications)

@app.route('/messages')
def messages():
    if 'guest' in session:
        flash('Misafir kullanıcılar mesajlara erişemez!')
        return redirect(url_for('nells'))
    if 'username' not in session:
        return redirect(url_for('login'))
    
    users = load_users()
    messages = load_messages()
    current_user = session['username']
    
    # Kullanıcının tüm konuşmalarını bul
    conversations = {}
    for msg in messages:
        other_user = None
        if msg['sender'] == current_user:
            other_user = msg['recipient']
        elif msg['recipient'] == current_user:
            other_user = msg['sender']
        
        if other_user and other_user in users:
            if other_user not in conversations:
                conversations[other_user] = {
                    'last_message': msg,
                    'unread_count': 0
                }
            else:
                # En son mesajı güncelle
                if msg['timestamp'] > conversations[other_user]['last_message']['timestamp']:
                    conversations[other_user]['last_message'] = msg
    
    # Konuşmaları son mesaj tarihine göre sırala
    sorted_conversations = sorted(conversations.items(), 
                                key=lambda x: x[1]['last_message']['timestamp'], 
                                reverse=True)
    
    return render_template('messages.html', conversations=sorted_conversations, users=users)

@app.route('/video_player')
def video_player():
    if 'username' not in session and 'guest' not in session:
        return redirect(url_for('index'))
    
    is_guest = 'guest' in session
    return render_template('video_player.html', is_guest=is_guest)

@app.route('/get_unread_message_count')
def get_unread_message_count():
    if 'username' not in session:
        return jsonify({'count': 0})
    
    messages = load_messages()
    current_user = session['username']
    unread_count = 0
    
    for msg in messages:
        if (msg['recipient'] == current_user and 
            not msg.get('read', False) and 
            not msg.get('deleted', False)):
            unread_count += 1
    
    return jsonify({'count': unread_count})

@app.route('/get_all_videos')
def get_all_videos():
    posts = load_posts()
    videos = []
    
    for post in posts:
        if post.get('is_public', True) and post.get('media_files'):
            for media_file in post['media_files']:
                if media_file.get('type') == 'video':
                    videos.append({
                        'post_id': post['id'],
                        'username': post['username'],
                        'content': post['content'],
                        'path': media_file['path'],
                        'filename': media_file['filename'],
                        'created_at': post['created_at']
                    })
    
    # Tarihe göre sırala (en yeni üstte)
    videos.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({'videos': videos})

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5007, debug=True)