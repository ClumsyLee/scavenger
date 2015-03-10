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

def arp_scan():
    """Generate (IP, MAC) pairs using arp-scan"""
    proc = subprocess.Popen(['sudo', 'arp-scan', '-lq'], stdout=subprocess.PIPE)
    out = proc.stdout
    # Skip the first two lines.
    next(out)
    next(out)
    # Parse IPs & MACs
    for line in out:
        infos = line.split()
        if not infos:  # Empty line at the end of the output
            return
        if len(infos) < 2:
            raise RuntimeError('Invalid output of arp-scan: "%s"' % line)
        yield (infos[0], infos[1])  # Generate (IP, MAC)
