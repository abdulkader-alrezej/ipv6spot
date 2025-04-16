import random
import ipaddress
from flask import Flask, render_template, redirect, request, url_for, session, make_response
import subprocess
import sqlite3
import re
import threading
import time
import datetime
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
#
# Abdulkader Alrezej
os.environ['FLASK_ENV'] = 'production'
app = Flask(__name__, template_folder='/mnt/cerr/web_dist/html_page', static_folder='/mnt/cerr/web_dist/img')
app.secret_key = os.environ.get('SECRET_KEY', '0000')
user_threads = {}
previous_usages = {}
def run_nft_command(command):
    try:
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
def add_ip_to_nft(ip_address):
    run_nft_command(['nft', 'add', 'element', 'ip6', 'nat', 'excluded_addrs', f'{{ {ip_address} }}'])
def remove_ip_from_nft(ip_address):
    try:
        run_nft_command(['nft', 'delete', 'element', 'ip6', 'nat', 'excluded_addrs', f'{{ {ip_address} }}'])
        run_nft_command(['conntrack', '-D', '--src', ip_address])
        run_nft_command(['conntrack', '-D', '--dst', ip_address])
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
def get_mac_from_ip(ip_address):
    try:
        output = subprocess.check_output(['ip', '-6', 'nei'], text=True)
        for line in output.splitlines():
            if ip_address in line:
                match = re.search(r'lladdr (\S+)', line)
                if match:
                    return match.group(1)
    except subprocess.CalledProcessError:
        pass
    return None
def get_all_ips_for_mac(mac_address):
    try:
        output = subprocess.check_output(['ip', '-6', 'nei'], text=True)
        ips = []
        for line in output.splitlines():
            if mac_address in line:
                match = re.search(r'(\S+) dev', line)
                if match:
                    ips.append(match.group(1))
        return ips
    except subprocess.CalledProcessError:
        pass
    return []
def run_tc_command(command):
    try:
        subprocess.run(command, check=True, text=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
def ipv6_to_tc_matches(ipv6_address):
    full_ipv6 = ipaddress.IPv6Address(ipv6_address).exploded
    ipv6_parts = full_ipv6.split(":")
    binary_parts = []
    for part in ipv6_parts:
        binary_parts.append(part.zfill(4))
    matches = []
    for i in range(0, len(binary_parts), 2):
        matches.append(binary_parts[i] + binary_parts[i + 1])
    return matches
def is_ip_in_tc_filter(ip_address):
    try:
        output = subprocess.check_output(['tc', 'filter', 'show', 'dev', 'br-lan'], text=True)
        matches = ipv6_to_tc_matches(ip_address)
        formatted_ip = ':'.join(matches)
        extracted_address_parts = []
        for line in output.splitlines():
            if 'match' in line:
                match_parts = re.findall(r'([a-f0-9]{8})/ffffffff', line)
                if match_parts:
                    extracted_address_parts.extend(match_parts)
            if len(extracted_address_parts) == 4:
                matched_address = ':'.join(extracted_address_parts)
                if matched_address == formatted_ip:
                    return True
                else:
                    extracted_address_parts = []
    except subprocess.CalledProcessError as e:
        print(f"Error checking tc filter: {e}")
    return False
def add_ip_to_tc_filter(ip_address, tc_id, upload_speed):
    if not is_ip_in_tc_filter(ip_address):
        run_tc_command(['tc', 'filter', 'add', 'dev', 'br-lan', 'protocol', 'ipv6', 'prio', '1', 'u32', 'match', 'ip6', 'dst', ip_address, 'flowid', f'1:{tc_id}'])
        run_tc_command(['tc', 'filter', 'add', 'dev', 'br-lan', 'parent', 'ffff:', 'protocol', 'ipv6', 'prio', '1', 'u32', 'match', 'ip6', 'src', ip_address, 'police', 'rate', upload_speed, 'burst', '50k', 'flowid', f'1:{tc_id}'])
    else:
        pass
def add_tc_class(tc_id, download_speed):
    run_tc_command(['tc', 'class', 'add', 'dev', 'br-lan', 'parent', '1:', 'classid', f'1:{tc_id}', 'htb', 'rate', download_speed, 'burst', '50k'])
def remove_ip_from_tc(tc_id):
    try:
        output = subprocess.check_output(['tc', 'filter', 'show', 'dev', 'br-lan'], text=True)
        flowid = f"flowid 1:{tc_id}"
        for line in output.splitlines():
            if flowid in line:
                handle_match = re.search(r'fh (\S+)', line)
                if handle_match:
                    handle = handle_match.group(1)
                    run_tc_command(['tc', 'filter', 'del', 'dev', 'br-lan', 'parent', '1:', 'handle', handle, 'prio', '1', 'protocol', 'ipv6', 'u32'])
        output_ff = subprocess.check_output(['tc', 'filter', 'show', 'dev', 'br-lan', 'parent', 'ffff:'], text=True)
        flowid = f"flowid 1:{tc_id}"
        for line in output_ff.splitlines():
            if flowid in line:
                handle_match = re.search(r'fh (\S+)', line)
                if handle_match:
                    handle = handle_match.group(1)
                    run_tc_command(['tc', 'filter', 'del', 'dev', 'br-lan', 'parent', 'ffff:', 'handle', handle, 'pref', '1', 'protocol', 'ipv6', 'u32'])
    except subprocess.CalledProcessError as e:
        print(f"Error removing IP from tc filter: {e}")
    try:
        run_tc_command(['tc', 'class', 'del', 'dev', 'br-lan', 'parent', '1:', 'classid', f'1:{tc_id}'])
    except subprocess.CalledProcessError as e:
        print(f"Error removing tc class: {e}")
def init_tc():
    run_tc_command(['tc', 'qdisc', 'del', 'dev', 'br-lan', 'root'])
    run_tc_command(['tc', 'qdisc', 'del', 'dev', 'br-lan', 'ingress'])
    run_tc_command(['tc', 'qdisc', 'add', 'dev', 'br-lan', 'root', 'handle', '1:', 'htb', 'default', '10'])
    run_tc_command(['tc', 'qdisc', 'add', 'dev', 'br-lan', 'handle', 'ffff:', 'ingress'])
def init_ip6tables():
    commands = [
        ['ip6tables', '-F'],
        ['ip6tables', '-X'],
        ['ip6tables', '-N', 'USER_IN'],
        ['ip6tables', '-N', 'USER_OUT'],
        ['ip6tables', '-A', 'FORWARD', '-j', 'USER_IN'],
        ['ip6tables', '-A', 'FORWARD', '-j', 'USER_OUT']
    ]
    for command in commands:
        run_nft_command(command)
def update_db_schema():
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = [info[1] for info in cursor.fetchall()]
        if 'max_data' not in columns:
            cursor.execute('''
                ALTER TABLE users ADD COLUMN max_data INTEGER DEFAULT 1073741824
            ''')
        if 'allowed_days' not in columns:
            cursor.execute('''
                ALTER TABLE users ADD COLUMN allowed_days INTEGER DEFAULT 1
            ''')
        conn.commit()
def add_ip_to_db(username, ip_address, role, tc_id):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO client_ips (username, ip_address, role, tc_id)
            VALUES (?, ?, ?, ?)
        ''', (username, ip_address, role, tc_id))
        conn.commit()
def remove_ip_from_db(username, ip_address):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            DELETE FROM client_ips
            WHERE username = ? AND ip_address = ?
        ''', (username, ip_address))
        conn.commit()
def get_ips_for_user(username):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address FROM client_ips
            WHERE username = ?
        ''', (username,))
        rows = cursor.fetchall()
        return [row[0] for row in rows]
def get_master_ip_for_user(username):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address FROM client_ips
            WHERE username = ? AND role = 'master'
        ''', (username,))
        row = cursor.fetchone()
        return row[0] if row else None
def get_tc_id_for_ip(ip_address):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT tc_id FROM client_ips
            WHERE ip_address = ?
        ''', (ip_address,))
        row = cursor.fetchone()
        return row[0] if row else None
def get_username_for_ip(ip_address):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT username FROM client_ips
            WHERE ip_address = ?
        ''', (ip_address,))
        row = cursor.fetchone()
        return row[0] if row else None
def validate_user(username, password):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT password_hash FROM users
            WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row and check_password_hash(row[0], password):
            return True
        return False
def get_user_speeds(username):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT download_speed, upload_speed FROM users
            WHERE username = ?
        ''', (username,))
        row = cursor.fetchone()
        if row:
            return row[0], row[1]
        return '1mbit', '512kbit'
def parse_datetime(date_str):
    try:
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S.%f')
    except ValueError:
        return datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')
def add_user_session(tc_id, username, master_ip, link_local_ip):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_sessions (tc_id, username, master_ip, link_local_ip)
            VALUES (?, ?, ?, ?)
        ''', (tc_id, username, master_ip, link_local_ip))
        conn.commit()
def end_user_session(tc_id):
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        end_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('''
            UPDATE user_sessions
            SET session_end = ?
            WHERE tc_id = ? AND session_end IS NULL
        ''', (end_time, tc_id))
        conn.commit()
        remove_ip_from_tc(tc_id)
def add_ip_to_ip6tables(ip_address):
    run_nft_command(['ip6tables', '-A', 'USER_IN', '-s', ip_address, '-j', 'RETURN'])
    run_nft_command(['ip6tables', '-A', 'USER_OUT', '-d', ip_address, '-j', 'RETURN'])
def remove_ip_from_ip6tables(ip_address):
    try:
        run_nft_command(['ip6tables', '-D', 'USER_IN', '-s', ip_address, '-j', 'RETURN'])
        run_nft_command(['ip6tables', '-D', 'USER_OUT', '-d', ip_address, '-j', 'RETURN'])
    except subprocess.CalledProcessError as e:
        print(f"Error removing IP from ip6tables: {e}")
def get_usage_data(ip_address):
    try:
        download_usage = subprocess.check_output(
            f"nft list table ip6 filter | awk '/ip6 daddr {ip_address}/ {{print $(NF-1)}}'",
            shell=True, text=True
        ).strip()
        upload_usage = subprocess.check_output(
            f"nft list table ip6 filter | awk '/ip6 saddr {ip_address}/ {{print $(NF-1)}}'",
            shell=True, text=True
        ).strip()
        download_usage = int(download_usage) if download_usage else 0
        upload_usage = int(upload_usage) if upload_usage else 0

        return download_usage, upload_usage
    except subprocess.CalledProcessError as e:
        print(f"Error fetching usage data: {e}")
        return 0, 0
def update_usage_in_db(tc_id, ip_address):
    download_usage, upload_usage = get_usage_data(ip_address)
    if ip_address in previous_usages:
        prev_download, prev_upload = previous_usages[ip_address]
        actual_download = max(download_usage - prev_download, 0)
        actual_upload = max(upload_usage - prev_upload, 0)
    else:
        actual_download = download_usage
        actual_upload = upload_usage
    previous_usages[ip_address] = (download_usage, upload_usage)
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE user_sessions
            SET download_usage = download_usage + ?, upload_usage = upload_usage + ?, session_last_update = ?
            WHERE tc_id = ?
        ''', (actual_download, actual_upload, current_time, tc_id))
        conn.commit()
def ping_ip(ip_address):
    ping_successful = False
    for _ in range(2): 
        try:
            subprocess.check_output(['ping', '-c', '1', ip_address], stderr=subprocess.STDOUT, text=True)
            ping_successful = True
            break
        except subprocess.CalledProcessError:
            continue
    if ping_successful:
        return True
    nmap_successful = False
    for _ in range(5):
        try:
            output = subprocess.check_output(['nmap', '-6', '-sn', ip_address], stderr=subprocess.STDOUT, text=True)
            if "Host is up" in output:
                nmap_successful = True
                break
        except subprocess.CalledProcessError:
            continue
    return nmap_successful
def periodic_ip_check(username, mac_address, tc_id, stop_event):
    master_ip = get_master_ip_for_user(username)
    while not stop_event.is_set():
        all_ips = get_all_ips_for_mac(mac_address)
        existing_ips = get_ips_for_user(username)
        link_local_ips = [ip for ip in all_ips if ip.startswith('fe80::')]
        if len(link_local_ips) > 1:
            logout_user(username, tc_id)
            return
        with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT SUM(download_usage + upload_usage)
                FROM user_sessions
                WHERE username = ?
            ''', (username,))
            total_usage = cursor.fetchone()[0] or 0
            cursor.execute('''
                SELECT max_data, allowed_days FROM users WHERE username = ?
            ''', (username,))
            max_data, allowed_days = cursor.fetchone()
            if total_usage >= max_data:
                with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE users
                        SET reason = 'maxdata'
                        WHERE username = ?
                    ''', (username,))
                    conn.commit()
                logout_user(username, tc_id)
                return
            cursor.execute('''
                SELECT MIN(session_start), MAX(session_end)
                FROM user_sessions
                WHERE username = ?
            ''', (username,))
            session_start, session_end = cursor.fetchone()
            if session_start:
                session_start = parse_datetime(session_start).strftime('%Y-%m-%d %H:%M:%S')
                if session_end:
                    session_end = parse_datetime(session_end).strftime('%Y-%m-%d %H:%M:%S')
                else:
                    session_end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                days_used = (datetime.strptime(session_end, '%Y-%m-%d %H:%M:%S') - datetime.strptime(session_start, '%Y-%m-%d %H:%M:%S')).days
                if days_used >= allowed_days:
                    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            UPDATE users
                            SET reason = 'maxdays'
                            WHERE username = ?
                        ''', (username,))
                        conn.commit()
                    logout_user(username, tc_id)
                    return
        for ip in all_ips:
            if ip not in existing_ips:
                add_ip_to_nft(ip)
                add_ip_to_db(username, ip, 'slave', tc_id)
                add_ip_to_tc_filter(ip, tc_id, get_user_speeds(username)[1])
                add_ip_to_ip6tables(ip)
        if master_ip and not ping_ip(master_ip):
            logout_user(username, tc_id)
        for ip in all_ips:
            update_usage_in_db(tc_id, ip)
        stop_event.wait(2)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.remote_addr
        username = get_username_for_ip(client_ip)
        if username:
            with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT 1 FROM client_ips WHERE ip_address = ?
                ''', (client_ip,))
                ip_exists = cursor.fetchone()
            if ip_exists:
                session['username'] = username
                session['client_ip'] = client_ip
                if request.path == '/welcome':
                    return f(*args, **kwargs)
                else:
                    return redirect('/welcome')
        return redirect('/login')
    return decorated_function
@app.route('/')
def index():
    return redirect('/welcome')
@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name_network FROM info_admin LIMIT 1")
        result = cursor.fetchone()
        if result and len(result) > 0:
            system_name = result[0]
        else:
            system_name = "IPv6Spot"
        print("System Name:", system_name)
    username = get_username_for_ip(client_ip)
    if username:
        with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM client_ips WHERE ip_address = ?
            ''', (client_ip,))
            ip_exists = cursor.fetchone()
        if ip_exists:
            session['username'] = username
            session['client_ip'] = client_ip
            return redirect('/welcome')
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me')
        with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 1 FROM user_sessions 
                WHERE username = ? AND session_end IS NULL
            ''', (username,))
            active_session = cursor.fetchone()

        if active_session:
            error = 'The user is currently in an active session.'
            return render_template('login.html', error=error, client_ip=client_ip)
        if validate_user(username, password):
            with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE user_sessions
                    SET session_end = ?
                    WHERE username = ? AND session_end IS NULL
                ''', (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), username))
                conn.commit()
                cursor.execute('''
                    SELECT SUM(download_usage + upload_usage)
                    FROM user_sessions
                    WHERE username = ?
                ''', (username,))
                total_usage = cursor.fetchone()[0] or 0
                cursor.execute('''
                    SELECT max_data, allowed_days FROM users WHERE username = ?
                ''', (username,))
                max_data, allowed_days = cursor.fetchone()
                if total_usage >= max_data:
                    error = 'You have exceeded your data limit.'
                    return render_template('login.html', error=error, client_ip=client_ip)
                cursor.execute('''
                    SELECT MIN(session_start), MAX(session_end)
                    FROM user_sessions
                    WHERE username = ?
                ''', (username,))
                session_start, session_end = cursor.fetchone()
                if session_start:
                    session_start = parse_datetime(session_start).strftime('%Y-%m-%d %H:%M:%S')
                    if session_end:
                        session_end = parse_datetime(session_end).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        session_end = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    days_used = (datetime.strptime(session_end, '%Y-%m-%d %H:%M:%S') - datetime.strptime(session_start, '%Y-%m-%d %H:%M:%S')).days
                    if days_used >= allowed_days:
                        error = 'You have exceeded the number of days allowed.'
                        return render_template('login.html', error=error, client_ip=client_ip)
            session['username'] = username
            session['client_ip'] = client_ip
            tc_id = random.randint(1000, 9999)
            session['tc_id'] = tc_id
            mac_address = get_mac_from_ip(client_ip)
            if mac_address:
                all_ips = get_all_ips_for_mac(mac_address)
                master_ip = client_ip
                link_local_ip = next((ip for ip in all_ips if ip.startswith('fe80::')), None)
                download_speed, upload_speed = get_user_speeds(username)
                add_ip_to_nft(master_ip)
                add_ip_to_db(username, master_ip, 'master', tc_id)
                add_tc_class(tc_id, download_speed)
                add_ip_to_tc_filter(master_ip, tc_id, upload_speed)
                add_ip_to_ip6tables(master_ip)
                for ip in all_ips:
                    if ip != master_ip:
                        add_ip_to_nft(ip)
                        add_ip_to_db(username, ip, 'slave', tc_id)
                        add_ip_to_tc_filter(ip, tc_id, upload_speed)
                        add_ip_to_ip6tables(ip)
                stop_event = threading.Event()
                thread = threading.Thread(target=periodic_ip_check, args=(username, mac_address, tc_id, stop_event), daemon=True)
                user_threads[username] = (thread, stop_event)
                thread.start()
                add_user_session(tc_id, username, master_ip, link_local_ip or master_ip)
            response = make_response(redirect('/welcome'))
            if remember_me:
                response.set_cookie('username', username, max_age=30*24*60*60)
                response.set_cookie('password', password, max_age=30*24*60*60)
            else:
                response.set_cookie('username', '', expires=0)
                response.set_cookie('password', '', expires=0)
            return response
        else:
            error = 'Incorrect username or password'
            return render_template('login.html', error=error, client_ip=client_ip)
    return render_template('login.html', client_ip=client_ip, system_name=system_name)
@app.route('/logout')
def logout():
    username = session.get('username')
    tc_id = session.get('tc_id')
    if username:
        if not tc_id:
            with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT tc_id FROM user_sessions
                    WHERE username = ? AND session_end IS NULL
                ''', (username,))
                row = cursor.fetchone()
                if row:
                    tc_id = row[0]
        if tc_id:
            logout_user(username, tc_id)
            end_user_session(tc_id)
    return redirect('/login')
def delete_ips_in_nei(mac_address):
    try:
        output = subprocess.check_output(['ip', '-6', 'nei'], text=True)
        for line in output.splitlines():
            if mac_address in line:
                match = re.search(r'(\S+) dev', line)
                if match:
                    ip_address = match.group(1)
                    subprocess.run(['ip', '-6', 'nei', 'del', ip_address, 'dev', 'br-lan'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error deleting IPs in nei for MAC {mac_address}: {e}")
def logout_user(username, tc_id):
    if username in user_threads:
        _, stop_event = user_threads[username]
        stop_event.set()
        del user_threads[username]
    mac_address = None
    ips = get_ips_for_user(username)
    if ips:
        mac_address = get_mac_from_ip(ips[0])
    for ip in ips:
        remove_ip_from_nft(ip)
        remove_ip_from_ip6tables(ip)
    remove_ip_from_tc(tc_id)
    for ip in ips:
        remove_ip_from_db(username, ip)
    if mac_address:
        delete_ips_in_nei(mac_address)
    end_user_session(tc_id)
    session.pop('username', None)
    session.pop('client_ip', None)
    session.pop('tc_id', None)
def format_size(size_in_bytes):
    if size_in_bytes >= 1024**3:
        size_in_gb = size_in_bytes / 1024**3
        return f"{size_in_gb:.2f} Gigabyte"
    elif size_in_bytes >= 1024**2:
        size_in_mb = size_in_bytes / 1024**2
        return f"{size_in_mb:.2f} Megabyte"
    elif size_in_bytes >= 1024:
        size_in_kb = size_in_bytes / 1024
        return f"{size_in_kb:.2f} Kilobytes"
    else:
        return f"{size_in_bytes} Byte"
@app.route('/welcome')
@login_required
def welcome():
    username = session.get('username')
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT max_data, allowed_days, download_speed, upload_speed 
            FROM users 
            WHERE username = ?
        ''', (username,))
        max_data, allowed_days, download_speed, upload_speed = cursor.fetchone()
        formatted_max_data = format_size(max_data)
        if download_speed.endswith('kbit'):
            download_speed = download_speed.replace('kbit', 'Kbps')
        elif download_speed.endswith('mbit'):
            download_speed = download_speed.replace('mbit', 'Mbps')
        if upload_speed.endswith('kbit'):
            upload_speed = upload_speed.replace('kbit', 'Kbps')
        elif upload_speed.endswith('mbit'):
            upload_speed = upload_speed.replace('mbit', 'Mbps')
        cursor.execute('''
            SELECT SUM(download_usage), SUM(upload_usage) 
            FROM user_sessions 
            WHERE username = ? AND session_end IS NULL
        ''', (username,))
        current_download_usage, current_upload_usage = cursor.fetchone()
        current_download_usage = current_download_usage or 0
        current_upload_usage = current_upload_usage or 0
        formatted_download_usage = format_size(current_download_usage)
        formatted_upload_usage = format_size(current_upload_usage)
        total_usage = current_download_usage + current_upload_usage
        formatted_total_usage = format_size(total_usage)
    return render_template('welcome.html', 
                           username=username, 
                           max_data=formatted_max_data, 
                           allowed_days=allowed_days, 
                           download_speed=download_speed, 
                           upload_speed=upload_speed,
                           download_usage=formatted_download_usage, 
                           upload_usage=formatted_upload_usage,
                           total_usage=formatted_total_usage)
def reset_tables():
    for username, (thread, stop_event) in user_threads.items():
        stop_event.set()
        thread.join()
    user_threads.clear()
    with sqlite3.connect('/mnt/cerr/main_sqlite3_database.db') as conn:
        cursor = conn.cursor()
        cursor.execute('DELETE FROM client_ips')
        cursor.execute('''
            UPDATE user_sessions
            SET session_end = session_last_update
            WHERE session_end IS NULL
        ''')
        conn.commit()

if __name__ == "__main__":
    reset_tables()
    init_tc()
    init_ip6tables()
    update_db_schema()
    app.run(host='::', port=8080, debug=False)
