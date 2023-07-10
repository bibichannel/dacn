from rcv import num_honey, SnortListener
from agent import QLearningTable

import sys
import time
import socket
import logging

CONTROLLER_IP = '172.17.0.7'
CONTROLLER_PORT = 51234

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
nwsock = None


def update():
    for episode in range(101):
        # initial observation
        observation = env.reset()
        
        while True:
            print("Episode ", episode, " running...")
            # RL choose action based on observation
            action = RL.choose_action(str(observation))

            # RL take action and get next observation and reward
            observation_, reward, done = env.step(action)

            # RL learn from this transition
            RL.learn(str(observation), action, reward, str(observation_))

            # swap observation
            observation = observation_

            # break while loop when end of this episode
            if done:
                break

def start_send(data):
    '''Open a client on Network Socket'''
    nwsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        nwsock.connect((CONTROLLER_IP, CONTROLLER_PORT))
    except Exception as e:
        logger.info("Network socket connection error: %s" % e)
        sys.exit(1)
    
    nwsock.sendall(bytes(data, encoding='utf8'))


if __name__ == "__main__":
    env = SnortListener()
    RL = QLearningTable(actions=list(range(env.n_actions)))
    update()
    start_send("1")
    print ("Number of honeypots: ", num_honey())
