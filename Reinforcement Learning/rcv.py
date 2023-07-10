import os
import time
import socket
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SOCKFILE = "/tmp/snort_alert"
BUFSIZE = 65863
checkMal = []
current_state = [1,0,0]
count_honeypot = 0
max_num = 0


class SnortListener():

    def __init__(self):
        self.unsock = None
        self.nwsock = None

        self.action_space = ['add', 'remove']
        self.n_actions = len(self.action_space)

    def start_recv(self):
        '''Open a server on Unix Domain Socket'''
        if os.path.exists(SOCKFILE):
            os.unlink(SOCKFILE)

        self.unsock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.unsock.bind(SOCKFILE)
        logger.info("Unix Domain Socket listening...")
        self.recv_loop()

    def recv_loop(self):
        global current_state, max_num, checkMal
        while True:
            data = self.unsock.recv(BUFSIZE)
            time.sleep(0.5)
            if data:
                attack_type = data.decode('latin1')[:4]

                checkMal.append(attack_type)

                if len(checkMal) == 20:
                    if 'Ping' in checkMal:
                        current_state[1] = 1
                        print('ICMP detected!')
                    if 'SSH' in checkMal:
                        current_state[2] = 2
                    max_num = len(set(checkMal))
                    print("max num: ", max_num, "\nCurrent state: ", current_state)
                    checkMal = []
                    break
            else:
                pass
    
    def reset(self):
        return [1,0,0]

    def step(self, action):
        s = self.reset()
        global count_honeypot
        if action == 0:
            count_honeypot += 1
        elif action == 1:
            count_honeypot -= 1
        s_ = current_state
        # reward function
        if (count_honeypot <= max_num):
            reward = 1
            done = True
            s_ = 'terminal'
        elif (count_honeypot > max_num):
            reward = 0
            done = False
        # print("Counting honeypots: ", count_honeypot)
        return s_, reward, done

    def render(self):
        time.sleep(0.1)

def num_honey():
    return 1


if __name__ == '__main__':
    server = SnortListener()
    server.start_recv()