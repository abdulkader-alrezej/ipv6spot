from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import humanize
import logging
import time
import random
import string
from scapy.all import sniff, IPv6, TCP, UDP
import subprocess
from sqlalchemy import PrimaryKeyConstraint, or_
import psutil
from sqlalchemy.sql import func
import re
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from io import BytesIO
import hashlib
import os
# Abdulkader Alrezej
log = logging.getLogger('werkzeug')
log.setLevel(logging.CRITICAL)
os.environ['FLASK_ENV'] = 'production'
app = Flask(__name__,
            template_folder='/mnt/cerr/web_dist/web/html_page',
            static_folder='//mnt/cerr/web_dist/web/img')
progress_cache = {}
app.secret_key = '0000'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////mnt/cerr/main_sqlite3_database.db'
db = SQLAlchemy(app)
class CardSettings(db.Model):
    __tablename__ = 'cardsetting'
    id = db.Column(db.Integer, primary_key=True)
    card_width = db.Column(db.Float, nullable=False)
    card_height = db.Column(db.Float, nullable=False)
    x_offset = db.Column(db.Float, nullable=False)
    y_offset = db.Column(db.Float, nullable=False)
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
class Session(db.Model):
    __tablename__ = 'session'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_accessed = db.Column(db.DateTime, default=datetime.utcnow)
    def update_last_accessed(self):
        self.last_accessed = datetime.utcnow()
class Users(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(80), primary_key=True, unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    original_password = db.Column(db.String(120), nullable=False)
    download_speed = db.Column(db.String(20), nullable=False)
    upload_speed = db.Column(db.String(20), nullable=False)
    max_data = db.Column(db.Integer, nullable=False)
    allowed_days = db.Column(db.Integer, nullable=False)
    profile_using = db.Column(db.String(80), nullable=True)
    description = db.Column(db.String(120), nullable=True, default=func.now())
    reason = db.Column(db.String(255))
class InfoAdmin(db.Model):
    __tablename__ = 'info_admin'
    id = db.Column(db.Integer, primary_key=True)
    name_network = db.Column(db.String(80), nullable=False)
class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    tc_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    session_start = db.Column(db.String(19), nullable=False)
    session_last_update = db.Column(db.String(19), nullable=False)
    session_end = db.Column(db.String(19))
    master_ip = db.Column(db.String(45), nullable=False)
    link_local_ip = db.Column(db.String(45), nullable=False)
    download_usage = db.Column(db.BigInteger, nullable=False)
    upload_usage = db.Column(db.BigInteger, nullable=False)
class ClientIP(db.Model):
    __tablename__ = 'client_ips'
    tc_id = db.Column(db.Integer, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    __table_args__ = (
        PrimaryKeyConstraint('tc_id', 'ip_address'),
    )
    def __init__(self, username):
        self.username = username
        self.is_active = True
        self.last_access = datetime.utcnow()
class UserProfile(db.Model):
    __tablename__ = 'users_profiles'
    name = db.Column(db.String(80), primary_key=True, nullable=False)
    download_speed = db.Column(db.String(20), nullable=False)
    upload_speed = db.Column(db.String(20), nullable=False)
    max_data = db.Column(db.BigInteger, nullable=False)
    allowed_days = db.Column(db.Integer, nullable=False)
prev_stats = {}
prev_time = time.time()
connections = {}
timeout = 10
def analyze_packet(packet):
    current_time = time.time()

    if IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        else:
            return
        connection_key = (src_ip, src_port, dst_ip, dst_port)
        connections[connection_key] = current_time
    expired_connections = [conn for conn, timestamp in connections.items() if current_time - timestamp > timeout]
    for conn in expired_connections:
        del connections[conn]
def start_sniffing():
    sniff(iface="br-lan", filter="tcp port 80 or tcp port 443 or udp port 53", prn=analyze_packet, store=0)
import threading
sniffing_thread = threading.Thread(target=start_sniffing)
sniffing_thread.daemon = True
sniffing_thread.start()
@app.route('/')
def index():
    return redirect(url_for('login'))

def cleanup_sessions():
    with app.app_context():
        now = datetime.utcnow()
        one_minute_ago = now - timedelta(minutes=1)
        expired_sessions = Session.query.filter(Session.last_accessed < one_minute_ago).all()
        for session in expired_sessions:
            db.session.delete(session)
        db.session.commit()
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            existing_session = Session.query.filter_by(username=username).first()
            if existing_session:
                one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
                if existing_session.last_accessed >= one_minute_ago:
                    error = 'You are already logged in from another device or session'
                    return render_template('login.html', error=error)
                else:
                    db.session.delete(existing_session)
                    db.session.commit()
            new_session = Session(username=username)
            db.session.add(new_session)
            db.session.commit()
            session['session_id'] = new_session.id
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)
def cleanup_sessions():
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)
    expired_sessions = Session.query.filter(Session.last_accessed < one_minute_ago).all()
    for session in expired_sessions:
        db.session.delete(session)
    db.session.commit()
@app.before_request
def before_request():
    session_id = session.get('session_id')
    if session_id:
        session_record = Session.query.get(session_id)
        if session_record:
            one_minute_ago = datetime.utcnow() - timedelta(minutes=1)
            if session_record.last_accessed < one_minute_ago:
                cleanup_sessions()
            session_record.update_last_accessed()
            db.session.commit()
@app.route('/dashboard')
def dashboard():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('dashboard.html')
@app.route('/home')
def home():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    active_count = UserSession.query.filter(UserSession.session_end == None).count()
    expired_days_count = Users.query.filter_by(reason='maxdays').count()
    expired_data_count = Users.query.filter_by(reason='maxdata').count()
    unused_cards_count = db.session.query(Users).filter(
    or_(Users.reason == '', Users.reason.is_(None))
    ).filter(
    ~db.session.query(UserSession.username).filter(UserSession.username == Users.username).exists()
    ).count()
    total_cards_count = Users.query.count()
    total_expired_cards_count = Users.query.filter(Users.reason != '').count()
    return render_template(
        'home.html',
        active_count=active_count,
        expired_days_count=expired_days_count,
        expired_data_count=expired_data_count,
        unused_cards_count=unused_cards_count,
        total_cards_count=total_cards_count,
        total_expired_cards_count=total_expired_cards_count
    )
@app.route('/reboot', methods=['POST'])
def reboot():
    os.system('reboot')
    return jsonify({'message': 'System is rebooting...'}), 200
@app.route('/active')
def active():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('active.html')
@app.route('/active_data')
def active_data():
    try:
        sessions = UserSession.query.filter(UserSession.session_end == None).all()
        session_data = []
        for session in sessions:
            if session.session_start is None or session.session_last_update is None:
                continue
            session_start_time = datetime.strptime(session.session_start, "%Y-%m-%d %H:%M:%S")
            session_last_time = datetime.strptime(session.session_last_update, "%Y-%m-%d %H:%M:%S")
            time_diff = session_last_time - session_start_time
            minutes_diff = time_diff.total_seconds() / 60
            hours_diff = minutes_diff / 60
            if hours_diff >= 1:
                session_time = f"{hours_diff:.1f} hours"
            else:
                session_time = f"{minutes_diff:.0f} minutes"
            download_usage_human = humanize.naturalsize(session.download_usage, binary=True)
            upload_usage_human = humanize.naturalsize(session.upload_usage, binary=True)
            session_data.append({
                'Session ID': session.tc_id,
                'User Name': session.username,
                'Start Session': session_start_time.strftime("%H:%M:%S"),
                'Session Time': session_time,
                'IP': session.master_ip,
                'Link': session.link_local_ip,
                'Down': download_usage_human,
                'Up': upload_usage_human
            })
        return jsonify(session_data)
    except Exception as e:
        return jsonify([]), 500
@app.route('/interface')
def interface():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('interface.html')
@app.route('/interface_data')
def interface_data():
    try:
        global prev_stats, prev_time
        interfaces = {
            'br-lan': 'LAN',
            'br-wan': 'WAN',
            'jool': 'NAT64'
        }
        curr_time = time.time()
        time_diff = curr_time - prev_time
        data = []
        for interface, display_name in interfaces.items():
            curr_recv, curr_sent = get_network_stats(interface)
            if interface not in prev_stats:
                prev_stats[interface] = (curr_recv, curr_sent)
                continue
            prev_recv, prev_sent = prev_stats[interface]
            sent_rate_bps = ((curr_sent - prev_sent) * 8) / time_diff
            recv_rate_bps = ((curr_recv - prev_recv) * 8) / time_diff
            sent_rate = format_data_rate(sent_rate_bps)
            recv_rate = format_data_rate(recv_rate_bps)
            data.append({
                "interface": display_name,
                "upload_rate": sent_rate,
                "download_rate": recv_rate,
                "sent_total": format_data_size(curr_sent),
                "received_total": format_data_size(curr_recv)
            })
            prev_stats[interface] = (curr_recv, curr_sent)
        prev_time = curr_time
        return jsonify(data)
    except Exception as e:
        return jsonify([]), 500
def get_network_stats(interface):
    with open('/proc/net/dev', 'r') as f:
        contents = f.read()
        for line in contents.splitlines():
            if interface in line:
                data = line.split()
                received = int(data[1])
                sent = int(data[9])
                return received, sent
    raise ValueError(f"Interface {interface} not found")
def format_data_rate(size_in_bits):
    for unit in ['bps', 'Kbps', 'Mbps', 'Gbps']:
        if size_in_bits < 1000:
            return f"{size_in_bits:.2f} {unit}"
        size_in_bits /= 1000
def format_data_size(size_in_bytes):
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024
def calculate_traffic_rate_individual(prev_stats, current_stats, interval):
    in_rate_bps = max((current_stats['in_bytes'] - prev_stats['in_bytes']) * 8 / interval, 0)
    out_rate_bps = max((current_stats['out_bytes'] - prev_stats['out_bytes']) * 8 / interval, 0)
    return in_rate_bps, out_rate_bps
@app.route('/firewall')
def firewall():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('firewall.html')
@app.route('/firewall_data')
def firewall_data():
    try:
        connection_data = []
        for (src_ip, src_port, dst_ip, dst_port), _ in connections.items():
            connection_data.append({
                'Source IPv6': src_ip,
                'Source Port': src_port,
                'Direction': '->',
                'Destination IPv6': dst_ip,
                'Destination Port': dst_port
            })
        return jsonify(connection_data)
    except Exception as e:
        return jsonify([]), 500
@app.route('/active_traffic')
def active_traffic():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('active_traffic.html')
@app.route('/active_traffic_data')
def active_traffic_data():
    try:
        active_sessions = UserSession.query.filter(UserSession.session_end == None).all()
        session_data = []
        for session in active_sessions:
            client_ips = ClientIP.query.filter(ClientIP.tc_id == session.tc_id).all()
            ip_addresses = [ip.ip_address for ip in client_ips]
            if not ip_addresses:
                continue
            current_stats = get_nft_stats(ip_addresses)
            if session.tc_id not in prev_stats:
                prev_stats[session.tc_id] = {'in_bytes': 0, 'out_bytes': 0}
            in_rate, out_rate = calculate_traffic_rate_individual(
                prev_stats[session.tc_id], current_stats, 1
            )
            prev_stats[session.tc_id] = current_stats
            session_data.append({
                'Session ID': session.tc_id,
                'User Name': session.username,
                'Up': format_data_rate(out_rate),
                'Down': format_data_rate(in_rate),
            })
        return jsonify(session_data)
    except Exception as e:
        return jsonify([]), 500
@app.route('/traffic_control')
def traffic_control():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('traffic_control.html')
def calculate_traffic_for_all_ips(tc_id):
    all_ips = ClientIP.query.filter(ClientIP.tc_id == tc_id).all()
    all_ip_addresses = [ip.ip_address for ip in all_ips]
    if not all_ip_addresses:
        return {'in_rate': 0, 'out_rate': 0}
    current_stats = get_nft_stats(all_ip_addresses)
    if tc_id not in prev_stats:
        prev_stats[tc_id] = {'in_bytes': 0, 'out_bytes': 0}
    in_rate, out_rate = calculate_traffic_rate_individual(
        prev_stats[tc_id], current_stats, 1
    )

    prev_stats[tc_id] = current_stats

    return {'in_rate': in_rate, 'out_rate': out_rate}

@app.route('/traffic_control_data')
def traffic_control_data():
    try:
        active_sessions = UserSession.query.filter(UserSession.session_end == None).all()
        session_data = []
        for session in active_sessions:
            master_ips = ClientIP.query.filter(ClientIP.tc_id == session.tc_id, ClientIP.role == 'master').all()
            master_ip_addresses = [ip.ip_address for ip in master_ips]
            if not master_ip_addresses:
                continue
            traffic_rates = calculate_traffic_for_all_ips(session.tc_id)
            in_rate = traffic_rates['in_rate']
            out_rate = traffic_rates['out_rate']
            user = Users.query.filter_by(username=session.username).first()
            if user:
                download_speed = convert_speed_to_bits(user.download_speed)
                upload_speed = convert_speed_to_bits(user.upload_speed)
                download_rate_percentage = (in_rate / download_speed) * 100 if download_speed else 0
                upload_rate_percentage = (out_rate / upload_speed) * 100 if upload_speed else 0
                download_color = get_traffic_light_color(download_rate_percentage)
                upload_color = get_traffic_light_color(upload_rate_percentage)
                download_traffic_light = f"<span class='traffic-light' style='color:{download_color};'>●</span> {format_data_rate(in_rate)}"
                upload_traffic_light = f"<span class='traffic-light' style='color:{upload_color};'>●</span> {format_data_rate(out_rate)}"
                session_data.append({
                    'Session ID': session.tc_id,
                    'User Name': session.username,
                    'IP Addresses': ", ".join(master_ip_addresses),
                    'Upload Rate': upload_traffic_light,
                    'Download Rate': download_traffic_light,
                })
        return jsonify(session_data)
    except Exception as e:
        return jsonify([]), 500
def convert_speed_to_bits(speed_str):
    units = {'kbit': 1000, 'mbit': 1000000}
    for unit in units:
        if unit in speed_str.lower():
            return int(speed_str.lower().replace(unit, '').strip()) * units[unit]
    return 0
def get_traffic_light_color(percentage):
    if percentage >= 90:
        return 'red'
    elif 50 <= percentage < 90:
        return 'yellow'
    elif percentage < 50:
        return 'green'
    return 'green'
def get_nft_stats(ip_addresses):
    stats = {
        'in_bytes': 0,
        'out_bytes': 0,
    }
    for ip_address in ip_addresses:
        result = subprocess.run(['nft', 'list', 'table', 'ip6', 'filter'], stdout=subprocess.PIPE)
        output = result.stdout.decode('utf-8')
        lines = output.split('\n')
        for line in lines:
            if f'ip6 daddr {ip_address} counter' in line:
                try:
                    stats['in_bytes'] += int(line.split('bytes')[1].strip().split()[0])
                except (IndexError, ValueError):
                    continue
            elif f'ip6 saddr {ip_address} counter' in line:
                try:
                    stats['out_bytes'] += int(line.split('bytes')[1].strip().split()[0])
                except (IndexError, ValueError):
                    continue
    return stats
@app.route('/user_profiles')
def user_profiles():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('user_profiles.html')
def format_speed(speed_str):
    value = int(''.join(filter(str.isdigit, speed_str)))
    unit = ''.join(filter(str.isalpha, speed_str))

    if unit == 'mbit':
        return f"{value} Mbps"
    elif unit == 'kbit':
        return f"{value} Kbps"
    return speed_str
def convert_bytes(size_in_bytes):
    for unit in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024
    return f"{size_in_bytes:.2f} TB"
@app.route('/user_profiles_data')
def user_profiles_data():
    try:
        search_query = request.args.get('search', '')
        if search_query:
            profiles = UserProfile.query.filter(UserProfile.name.ilike(f'%{search_query}%')).all()
        else:
            profiles = UserProfile.query.all()
        profiles_data = []
        for profile in profiles:
            download_speed = format_speed(profile.download_speed)
            upload_speed = format_speed(profile.upload_speed)
            data_limit = convert_bytes(profile.max_data)
            day_limit = f"{profile.allowed_days} Days"
            profiles_data.append({
                'Name': profile.name,
                'Download Limit': download_speed,
                'Upload Limit': upload_speed,
                'Data Limit': data_limit,
                'Day limit': day_limit,
            })
        return jsonify(profiles_data)
    except Exception as e:
        return jsonify([]), 500
@app.route('/check_name_exists')
def check_name_exists():
    name = request.args.get('name')
    profile = UserProfile.query.filter_by(name=name).first()
    return jsonify({'exists': profile is not None})

@app.route('/add_user_profile', methods=['POST'])
def add_user_profile():
    try:
        name = request.form.get('name')
        download_speed = request.form.get('download_speed')
        upload_speed = request.form.get('upload_speed')
        max_data_value = request.form.get('max_data')
        allowed_days = request.form.get('allowed_days')
        if not all([name, download_speed, upload_speed, max_data_value, allowed_days]):
            return jsonify({'success': False, 'message': 'Missing form data'}), 400
        max_data = int(max_data_value)
        existing_profile = UserProfile.query.filter_by(name=name).first()
        if existing_profile:
            return jsonify({'success': False, 'message': 'Name already exists'}), 400
        new_profile = UserProfile(
            name=name,
            download_speed=download_speed,
            upload_speed=upload_speed,
            max_data=max_data,
            allowed_days=int(allowed_days)
        )
        db.session.add(new_profile)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/delete_user_profiles', methods=['POST'])
def delete_user_profiles():
    try:
        data = request.get_json()
        names_to_delete = data.get('names', [])
        if not names_to_delete:
            return jsonify({'success': False, 'message': 'No profiles selected for deletion'}), 400
        UserProfile.query.filter(UserProfile.name.in_(names_to_delete)).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/add_users')
def add_users():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('add_users.html')
@app.route('/add_users_data')
def add_users_data():
    try:
        search_query = request.args.get('search', '')
        if search_query:
            users = Users.query.filter(
                Users.username.ilike(f'%{search_query}%'),
                Users.profile_using != '0'
            ).all()
        else:
            users = Users.query.filter(Users.profile_using != '0').all()
        users_data = []
        for user in users: 
            session = Users.query.filter_by(username=user.username).first()
            reason = session.reason if session and session.reason not in (None, '') else None
            users_data.append({
                'User Name': user.username,
                'Password': user.original_password,
                'Profile': user.profile_using,
                'Date': user.description,
                'Reason': reason
            })
        return jsonify(users_data)
    except Exception as e:
        return jsonify([]), 500
@app.route('/delete_users', methods=['POST'])
def delete_users():
    try:
        data = request.get_json()
        usernames_to_delete = data.get('usernames', [])
        if not usernames_to_delete:
            return jsonify({'success': False, 'message': 'No users selected for deletion'}), 400
        for username in usernames_to_delete:
            user = Users.query.filter_by(username=username).first()
            if not user:
                continue
            if not user.reason:
                active_session = UserSession.query.filter_by(username=username).first()
                if active_session:
                    return jsonify({'successa': True, 'message': f'User {username} is currently in use.'}), 200
                else:
                    Users.query.filter_by(username=username).delete(synchronize_session=False)
            else:
                UserSession.query.filter_by(username=username).delete(synchronize_session=False)
                Users.query.filter_by(username=username).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Users deleted successfully'}), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/get_profiles')
def get_profiles():
    profiles = UserProfile.query.all()
    profiles_data = [{'name': profile.name} for profile in profiles]
    return jsonify(profiles_data)
@app.route('/generate_and_add_users', methods=['POST'])
def generate_and_add_users():
    try:
        data = request.get_json()
        prefix = data.get('prefix')
        number_of_users = int(data.get('number'))
        selected_profile_name = data.get('profile')
        progress_key = f"progress_{prefix}"
        progress_cache[progress_key] = 0
        existing_user_with_prefix = Users.query.filter(Users.username.like(f'{prefix}%')).first()
        if existing_user_with_prefix:
            return jsonify({'success': False, 'message': 'Prefix already exists in the database'}), 400
        profile = UserProfile.query.filter_by(name=selected_profile_name).first()
        if not profile:
            return jsonify({'success': False, 'message': 'Profile not found'}), 400
        generated_users = []
        for i in range(number_of_users):
            username = prefix + ''.join(random.choices(string.ascii_lowercase, k=8))
            password = generate_random_password()
            password_hash = generate_password_hash(password)
            new_user = Users(
                username=username,
                password_hash=password_hash,
                original_password=password,
                download_speed=profile.download_speed,
                upload_speed=profile.upload_speed,
                max_data=profile.max_data,
                allowed_days=profile.allowed_days,
                profile_using=selected_profile_name,
            )
            db.session.add(new_user)
            db.session.commit()
            progress_cache[progress_key] = int((i + 1) / number_of_users * 100)
        return jsonify({'success': True, 'users': generated_users})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/progress/<prefix>', methods=['GET'])
def get_progress(prefix):
    progress_key = f"progress_{prefix}"
    progress = progress_cache.get(progress_key, 0)
    return jsonify({'progress': progress})

def generate_random_password():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))

def generate_unique_username(prefix, existing_usernames):
    while True:
        username = prefix + ''.join(random.choices(string.ascii_lowercase, k=8))
        if username not in existing_usernames:
            return username

@app.route('/add_one')
def add_one():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('add_one.html')
@app.route('/add_one_user', methods=['POST'])
def add_one_user():
    try:
        data = request.get_json()
        username = data.get('username')
        original_password = data.get('original_password')
        download_speed = convert_speed_to_db_format(data.get('download_speed'))
        upload_speed = convert_speed_to_db_format(data.get('upload_speed'))
        max_data_value = data.get('max_data')
        max_data_unit = data.get('data_unit')
        max_data = convert_data_limit_to_bytes(max_data_value, max_data_unit)
        allowed_days = data.get('allowed_days')
        existing_user = Users.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Username already exists'}), 400
        password_hash = generate_password_hash(original_password)
        new_user = Users(
            username=username,
            password_hash=password_hash,
            original_password=original_password,
            download_speed=download_speed,
            upload_speed=upload_speed,
            max_data=max_data,
            allowed_days=allowed_days,
            profile_using=0
        )
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
def convert_speed_to_db_format(speed):
    if 'Mbps' in speed:
        return speed.replace('Mbps', 'mbit')
    elif 'Kbps' in speed:
        return speed.replace('Kbps', 'kbit')
    return speed
def convert_data_limit_to_bytes(value, unit):
    try:
        value = int(value)
        if unit == "Mbyte":
            return value * 1024 * 1024
        elif unit == "Kbyte":
            return value * 1024
        elif unit == "Byte":
            return value
        else:
            raise ValueError(f"Unknown unit for data limit: {unit}")
    except Exception as e:
        raise
@app.route('/add_one_data', methods=['GET'])
def get_add_one_data():
    search_query = request.args.get('search', '')
    query = Users.query.filter_by(profile_using='0')
    if search_query:
        search_filter = f"%{search_query}%"
        query = query.filter(Users.username.ilike(search_filter))
    users = query.all()
    user_list = []
    for user in users:
        download_speed = convert_speed(user.download_speed)
        upload_speed = convert_speed(user.upload_speed)
        data_limit = convert_data_limit(user.max_data)
        user_list.append({
            'username': user.username,
            'original_password': user.original_password,
            'download_speed': download_speed,
            'upload_speed': upload_speed,
            'max_data': data_limit,
            'allowed_days': user.allowed_days,
            'description': user.description,
            'reason': user.reason
        })
    return jsonify(user_list)

def convert_speed(speed):
    if 'mbit' in speed.lower():
        return speed.lower().replace('mbit', 'Mbps')
    elif 'kbit' in speed.lower():
        return speed.lower().replace('kbit', 'Kbps')
    return speed
def convert_data_limit(bytes_value):
    bytes_value = int(bytes_value)
    if bytes_value >= 1073741824:
        return f"{bytes_value / 1073741824:.2f} GB"
    elif bytes_value >= 1048576:
        return f"{bytes_value / 1048576:.2f} MB"
    elif bytes_value >= 1024:
        return f"{bytes_value / 1024:.2f} KB"
    else:
        return f"{bytes_value} Byte"
@app.route('/print')
def print_page():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('print.html')
def convert_speed_to_bps(speed):
    if 'mbit' in speed:
        return speed.replace('mbit', 'Mbps')
    elif 'kbit' in speed:
        return speed.replace('kbit', 'Kbps')
    return speed
def convert_bytes_to_readable(data_in_bytes):
    data_in_bytes = int(data_in_bytes)
    if data_in_bytes >= 1_000_000_000:
        return f"{data_in_bytes / 1_000_000_000:.2f} GB"
    elif data_in_bytes >= 1_000_000:
        return f"{data_in_bytes / 1_000_000:.2f} MB"
    elif data_in_bytes >= 1_000:
        return f"{data_in_bytes / 1_000:.2f} KB"
    else:
        return f"{data_in_bytes} Bytes"
@app.route('/add_print', methods=['POST'])
def add_print():
    try:
        data = request.json
        usernames = data.get('usernames', [])
        if not usernames:
            return jsonify({'success': False, 'message': 'No users selected'}), 400
        users = Users.query.filter(Users.username.in_(usernames)).all()
        network_info = InfoAdmin.query.first()
        network_name = network_info.name_network if network_info else "IPv6Spot"
        card_settings = CardSettings.query.first()
        if card_settings:
            card_width = card_settings.card_width * inch
            card_height = card_settings.card_height * inch
            x_offset = card_settings.x_offset * inch
            y_offset = card_settings.y_offset * inch
        else:
            card_width = 2.0 * inch
            card_height = 3.5 * inch
            x_offset = 0.125 * inch
            y_offset = 0.125 * inch
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        x = x_offset
        y = height - card_height - y_offset
        for i, user in enumerate(users):
            if i > 0 and i % 4 == 0:
                x = x_offset
                y -= card_height + y_offset
            if y < y_offset:
                c.showPage()
                x = x_offset
                y = height - card_height - y_offset
            speed_converted = convert_speed_to_bps(user.download_speed)
            data_converted = convert_bytes_to_readable(user.max_data)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(x + 10, y + card_height - 20, f"{network_name}")
            c.setFont("Helvetica", 10)
            c.drawString(x + 10, y + card_height - 35, f"Username: {user.username}")
            c.drawString(x + 10, y + card_height - 50, f"Password: {user.original_password}")
            c.drawString(x + 10, y + card_height - 65, f"Speed: {speed_converted}")
            c.drawString(x + 10, y + card_height - 80, f"Data: {data_converted}")
            c.drawString(x + 10, y + card_height - 95, f"Days: {user.allowed_days}")
            c.drawString(x + 10, y + card_height - 110, f"Profile: {user.profile_using}")
            c.rect(x, y, card_width, card_height)
            x += card_width + x_offset
        c.save()
        buffer.seek(0)
        pdf_size = buffer.getbuffer().nbytes
        return send_file(buffer, as_attachment=True, download_name='user_cards.pdf', mimetype='application/pdf')
    except Exception as e:
        return jsonify({'success': False, 'message': 'An error occurred while generating the PDF.'}), 500
@app.route('/set_card_size', methods=['POST'])
def set_card_size():
    try:
        data = request.json
        card_width = data.get('card_width')
        card_height = data.get('card_height')
        x_offset = data.get('x_offset')
        y_offset = data.get('y_offset')

        setting = CardSettings.query.first()
        if setting is None:
            setting = CardSettings(card_width=card_width, card_height=card_height, x_offset=x_offset, y_offset=y_offset)
            db.session.add(setting)
        else:
            setting.card_width = card_width
            setting.card_height = card_height
            setting.x_offset = x_offset
            setting.y_offset = y_offset
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to update card size.'}), 500
@app.route('/get_card_size', methods=['GET'])
def get_card_size():
    try:
        setting = CardSettings.query.first()
        if setting:
            return jsonify({
                'success': True,
                'card_width': setting.card_width,
                'card_height': setting.card_height,
                'x_offset': setting.x_offset,
                'y_offset': setting.y_offset
            })
        else:
            return jsonify({'success': True, 'card_width': '', 'card_height': '', 'x_offset': '', 'y_offset': ''})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Failed to retrieve card size.'}), 500
@app.route('/fetch_prints', methods=['GET'])
def fetch_prints():
    search_query = request.args.get('search', '')
    query = Users.query.filter((Users.reason == None) | (Users.reason == '')).all()
    if search_query:
        query = [
            user for user in query 
            if search_query.lower() in user.username.lower() 
            or search_query.lower() in str(user.profile_using).lower()
        ]
    data = [
        {
            'username': user.username,
            'profile': user.profile_using,
            'date': user.description
        } for user in query
    ]
    return jsonify(data)
@app.route('/delete_prints', methods=['POST'])
def delete_prints():
    try:
        data = request.json
        usernames_to_delete = data.get('documents', [])
        if not usernames_to_delete:
            return jsonify({'success': False, 'message': 'No users selected for deletion'}), 400
        for username in usernames_to_delete:
            user_row = Users.query.filter_by(username=username).first()
            if not user_row:
                continue
            if not user_row.reason:
                active_session = UserSession.query.filter_by(username=username).first()
                if active_session:
                    return jsonify({'successa': True, 'message': f'User {username} is currently in use.'}), 200
                else:
                    Users.query.filter_by(username=username).delete(synchronize_session=False)
            else:
                UserSession.query.filter_by(username=username).delete(synchronize_session=False)
                Users.query.filter_by(username=username).delete(synchronize_session=False)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Users deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/user_usage')
def user_usage():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('user_usage.html')
def convert_size_user_usage_data(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_name[i]}"
@app.route('/user_usage_data')
def user_usage_data():
    search_query = request.args.get('search', '').strip()
    query = db.session.query(
        UserSession.username,
        func.min(UserSession.session_start).label('FirstLogin'),
        func.sum(UserSession.download_usage).label('DownloadUsage'),
        func.sum(UserSession.upload_usage).label('UploadUsage'),
        func.count(UserSession.session_start).label('LoginTimes'),
        (func.julianday(func.max(UserSession.session_end)) - func.julianday(func.min(UserSession.session_start))).label('DaysUsed'),
        Users.max_data
    ).join(Users, UserSession.username == Users.username)
    if search_query:
        query = query.filter(UserSession.username.ilike(f'%{search_query}%'))
    query = query.filter(UserSession.session_end.isnot(None))
    query = query.group_by(UserSession.username)
    results = query.all()
    data = []
    for result in results:
        usage_total = result.DownloadUsage + result.UploadUsage
        usage_percentage = (usage_total / result.max_data) * 100
        if usage_percentage > 100:
            usage_percentage = 100
        days_used = result.DaysUsed
        if days_used < 1:
            days_used = round(days_used * 24)
            days_used_str = f"{days_used} hours"
        else:
            days_used = int(days_used)
            days_used_str = f"{days_used} days"
        data.append({
            'Username': result.username,
            'First Login': result.FirstLogin,
            'Download Usage': convert_size_user_usage_data(result.DownloadUsage),
            'Upload Usage': convert_size_user_usage_data(result.UploadUsage),
            'Usage Total': usage_percentage,
            'Days Used': days_used_str,
            'Login Times': result.LoginTimes
        })
    return jsonify(data)

@app.route('/block_website')
def block_website():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('block_website.html')
@app.route('/block_website_data')
def block_website_data():
    try:
        websites = []
        with open('/mnt/cerr/external_domains.txt', 'r') as file:
            lines = file.readlines()
            for idx, line in enumerate(lines, start=1):
                websites.append({'ID': idx, 'Website': line.strip()})
        return jsonify(websites)
    except Exception as e:
        return jsonify([]), 500
@app.route('/add_website', methods=['POST'])
def add_website():
    try:
        website = request.form.get('website')
        if website:
            with open('/mnt/cerr/external_domains.txt', 'a') as file:
                file.write(website + '\n')
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/delete_website', methods=['POST'])
def delete_website():
    try:
        website = request.form.get('website')
        if not website:
            return jsonify({'success': False, 'message': 'No website provided'}), 400
        with open('/mnt/cerr/external_domains.txt', 'r') as file:
            lines = file.readlines()
        with open('/mnt/cerr/external_domains.txt', 'w') as file:
            for line in lines:
                if line.strip() != website:
                    file.write(line)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/settings', methods=['GET'])
def settings():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    return render_template('settings.html')
@app.route('/change_password', methods=['POST'])
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    user = User.query.filter_by(id=session['user_id']).first()
    if not user or not check_password_hash(user.password, current_password):
        return jsonify(success=False, message="Current password is incorrect.")
    hashed_password = generate_password_hash(new_password)
    user.password = hashed_password
    db.session.commit()
    return jsonify(success=True)
@app.route('/change_network_name', methods=['POST'])
def change_network_name():
    new_network_name = request.form.get('new_network_name')
    info_admin = InfoAdmin.query.first()
    if not info_admin:
        return jsonify(success=False, message="Network info not found.")
    info_admin.name_network = new_network_name
    db.session.commit()
    return jsonify(success=True)
@app.route('/get_current_network_name')
def get_current_network_name():
    try:
        info_admin = InfoAdmin.query.first()
        if info_admin:
            return jsonify({'success': True, 'current_network_name': info_admin.name_network})
        else:
            return jsonify({'success': False, 'message': 'Network name not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/db_management')
def db_management():
    session_id = session.get('session_id')
    if not session_id:
        return redirect(url_for('login'))
    session_record = Session.query.get(session_id)
    if not session_record:
        return redirect(url_for('login'))
    session_record.update_last_accessed()
    db.session.commit()
    backup_dir = '/mnt/cerr/db/backup/'
    files = []
    for file_name in os.listdir(backup_dir):
        if file_name.endswith('.encrypted'):
            file_path = os.path.join(backup_dir, file_name)
            creation_time = os.path.getctime(file_path)
            creation_date = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%d %H:%M:%S')
            files.append({
                'name': file_name,
                'date': creation_date
            })
    return render_template('db_management.html', files=files)
@app.route('/download_backup/<filename>')
def download_backup(filename):
    backup_dir = '/mnt/cerr/db/backup/'
    file_path = os.path.join(backup_dir, filename)
    return send_file(file_path, as_attachment=True)
def load_key(key_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    return key
def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as file:
        original_data = file.read()
    ciphertext, tag = cipher.encrypt_and_digest(original_data)
    with open(file_path + '.encrypted', 'wb') as enc_file:
        for x in (cipher.nonce, tag, ciphertext):
            enc_file.write(x)
def decrypt_file(enc_file_path, key, output_path):
    with open(enc_file_path, 'rb') as enc_file:
        nonce, tag, ciphertext = [enc_file.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_path, 'wb') as dec_file:
        dec_file.write(decrypted_data)
@app.route('/backup_database')
def backup_database():
    try:
        db_path = '/mnt/cerr/main_sqlite3_database.db'
        backup_dir = '/mnt/cerr/db/backup/'
        backup_file_path = os.path.join(backup_dir, 'client_data.db.encrypted')
        key_path = '/mnt/cerr/db/key/encryption_key.key'
        key = load_key(key_path)
        if not os.path.exists(backup_dir):
            os.makedirs(backup_dir)
        encrypt_file(db_path, key)
        os.rename(db_path + '.encrypted', backup_file_path)
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
@app.route('/restore_database', methods=['POST'])
def restore_database():
    try:
        logging.info("Starting database restore process...")
        file = request.files['file']
        key_path = '/mnt/cerr/db/key/encryption_key.key'
        key = load_key(key_path)
        temp_file_path = '/mnt/cerr/db/' + file.filename
        file.save(temp_file_path)
        output_path = '/mnt/cerr/main_sqlite3_database.db'
        decrypt_file(temp_file_path, key, output_path)
        os.remove(temp_file_path)
        logging.info("Database restore process completed successfully.")
        return jsonify({'success': True})
    except Exception as e:
        logging.error(f"Database restore failed: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/logout')
def logout():
    session_id = session.pop('session_id', None)
    if session_id:
        session_record = Session.query.get(session_id)
        if session_record:
            db.session.delete(session_record)
            db.session.commit()
    return redirect(url_for('login'))

@app.route('/cpu_usage')
def cpu_usage():
    try:
        cpu_usage_percentage = psutil.cpu_percent(interval=1)
        return jsonify({"cpu_usage": cpu_usage_percentage})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
def format_uptime(uptime_seconds):
    days, remainder = divmod(uptime_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    if days > 0:
        return f"{days}d {hours:02}:{minutes:02}:{seconds:02}"
    else:
        return f"{hours:02}:{minutes:02}:{seconds:02}"

@app.route('/uptime')
def uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
        formatted_uptime = format_uptime(int(uptime_seconds))
        return jsonify({"uptime": formatted_uptime})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='::', port=8586, debug=False, use_reloader=False)
