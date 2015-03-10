import requests

def logged_in():
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

