import socket
import subprocess
import requests

def check_online():
    """Check whether the device has logged in.
    Return a dictionary containing:
        username
        byte
        duration (in seconds)
    Return False if no logged in
    """
    r = requests.post('http://net.tsinghua.edu.cn/cgi-bin/do_login',
                      data={'action': 'check_online'})
    if r:  # status: OK
        infos = r.text.split(',')
        if len(infos) == 5:  # Decode successfully
            return dict(username=infos[1],
                        byte=infos[2],
                        duration=infos[4])
    # Failed to get infos
    return False

def logout():
    r = requests.post('http://net.tsinghua.edu.cn/cgi-bin/do_logout')
    if r.text == 'logout_ok':
        return True
    else:
        return False

def arp_scanner(interface='en0'):
    """Generate (IP, MAC) pairs using arp-scan"""
    proc = subprocess.Popen(['sudo', 'arp-scan', '-lq', '-I', interface],
                            stdout=subprocess.PIPE)
    out = proc.stdout
    # Skip the first two lines.
    next(out)
    next(out)
    gate = parse_arp_info(next(out))
    if not gate:
        raise RuntimeError('No peers found by arp-scan')

    # Parse IPs & MACs
    for line in out:
        infos = parse_arp_info(line)
        if not infos:  # End of the list
            return
        if infos[1] != gate[1]:
            yield infos


def parse_arp_info(line):
    infos = line.split()
    if not infos:  # Empty line at the end of the output
        return None
    if len(infos) < 2:
        raise RuntimeError('Invalid output of arp-scan: "%s"' % line)

    return (infos[0], infos[1])  # Generate (IP, MAC)

def set_wifi(ssid='Tsinghua-5G'):
    """Connect to Wi-Fi (By default, Tsinghua-5G)"""
    subprocess.call(['networksetup', '-setairportnetwork', 'en0', ssid])

def spoof_mac(mac=None, interface='en0'):
    """Spoof MAC for a certain interface, return True if succeeded
    if mac is None, reset MAC of the interface"""
    args = ['sudo', 'spoof-mac']
    if mac is None:  # Reset
        args = ['reset']
    else:
        args = ['set', mac]

    result = subprocess.call(['sudo', 'spoof-mac'] + args + [interface])
    if result == 0:
        return True
    else:
        return False

def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return '127.0.0.1'

def parse_ip(ip_str):
    return map(int, ip_str.split('.'))

def ip_diff(ip1, ip2):
    """Return ip2 - ip1
    ip1/ip2 should like [*,*,*,*]"""
    diff = 0
    for i in range(4):
        diff = 256 * diff + ip2[i] - ip1[i]
    return diff

__ALL__ = [
    check_online,
    logout,
    arp_scanner,
    set_wifi,
    spoof_mac,
    get_ip,
    parse_ip,
    ip_diff
]
