import json
import uuid
import time
import threading
from datetime import datetime
from Crypto.Cipher import PKCS1_v1_5 as PKCS
from Crypto.PublicKey import RSA
from Crypto import Random


random_generator = Random.new().read

sys_running = True
nonces = []
ip_requests = {}

nonces_lock = threading.Lock()
ip_requests_lock = threading.Lock()


def encrypt_data(msg, pub_key):
    rsa_key = RSA.importKey(pub_key)
    cipher = PKCS.new(rsa_key)
    encrypted = cipher.encrypt(msg.encode('utf-8'))
    return encrypted


def decrypt_data(msg, priv_key):
    rsa_key = RSA.importKey(priv_key)
    cipher = PKCS.new(rsa_key)
    decrypted = cipher.decrypt(msg, 0)
    return decrypted.decode('utf-8')


def get_timestamp():
    dt = datetime.now()
    return str(int(datetime.timestamp(dt)))


def get_nonce():
    return uuid.uuid4().hex


# For colored priting purposes
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class IoTMonitor():
    def __init__(self):
        self.reg_devices = []
        self.reg_users = []
        self.sys_state = {}
        self.priv_keys = {}
        self.user_db = self._load_users()
        self.risky_states = self._load_risky_states()
        self.acl = self._load_acl()
        self.permission_checker = PermissionChecker()
        self.predictor = StatePredictor()

    
    def init_auth(self, username):
        rsa = RSA.generate(2048, random_generator)
        priv_key = rsa.exportKey()
        pub_key = rsa.publickey().exportKey()
        self.priv_keys[username] = priv_key
        return pub_key

    # Login function for user
    def auth(self, username, ip, msg):
        if ip_requests.get(ip, 0) > 10:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! REQUEST FROM IP %s IS TOO FREQUENT. ACCESS DENIED.{bcolors.ENDC}" % ip)
            return False
        if ip_requests.get(ip) is None:
            ip_requests[ip] = 1
        else:
            ip_requests[ip] += 1

        msg = json.loads(decrypt_data(msg, self.priv_keys[username]))
        password, ts, nonce = msg["password"], msg["ts"], msg["nonce"]
        if int(get_timestamp()) - int(ts) > 15:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! RECEIVED DELAYED MESSAGE FROM USER %s (POSSIBLY REPLAY).{bcolors.ENDC}" % username)
            return False
        if nonce in nonces:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! RECEIVED REPEATED MESSAGE FROM USER %s (POSSIBLY REPLAY).{bcolors.ENDC}" % username)
            return False
        else:
            nonces.append(nonce)

        for u in self.user_db:
            if u['username'] == username \
            and u['password'] == password \
            and username not in self.reg_users:
                self.reg_users.append({"username": username, "group": u["group"]})
                print("[SERVER]: User %s connected to SERVER." % username)
                return True
        print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! USER %s: WRONG USERNAME OR PASSWORD.{bcolors.ENDC}" % username)
        return False

    # Logout function for user 
    def logout(self, username):
        target_idx = self._filter_user(username)
        if target_idx != -1:
            self.reg_users.pop(target_idx)
            print("[SERVER]: User %s disconnected from SERVER." % username)
            return True
        
        return False
    
    # Register device to server
    def bind(self, device):
        if device not in self.reg_devices:
            self.reg_devices.append(device)
            self.sys_state[device.name] = {}
            print("[SERVER]: Device %s registered at SERVER." % device.name)
            return True
        
        return False

    # Unregister device from server
    def unbind(self, device_name):
        target_idx = self._filter_device(device_name)
        device = self.reg_devices[target_idx]
        if target_idx != -1:
            self.reg_devices.pop(target_idx)
            del self.sys_state[device["name"]]
            print("[SERVER]: Device %s unregisterd at SERVER." % device["name"])
            return True
        
        return False

    # Execute command from user
    def execute(self, username, msg):
        msg = json.loads(decrypt_data(msg, self.priv_keys[username]))
        device_name, action, incoming_state = msg["device"], msg["action"], msg["incoming_state"]
        ts, nonce = msg["ts"], msg["nonce"]
        if int(get_timestamp()) - int(ts) > 3:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! RECEIVED DELAYED MESSAGE FROM USER %s (POSSIBLY REPLAY).{bcolors.ENDC}" % username)
            return False
        if nonce in nonces:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! RECEIVED REPEATED MESSAGE FROM USER %s (POSSIBLY REPLAY).{bcolors.ENDC}" % username)
            return False
        else:
            nonces.append(nonce)

        if self._filter_user(username) == -1:
            print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! USER %s ATTEMPTED UNAUTHORIZED ACCESS TO %s{bcolors.ENDC}" % (username, device_name))
            return False
        elif self._filter_device(device_name) == -1:
            print("[SERVER]: %s is not registered with server" % device_name)
            return False
        else:
            user = self.reg_users[self._filter_user(username)]
            # Check if user have corresponding permission on device
            if not self._check_permission(user, action, device_name):
                print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! USER %s DOES NOT HAVE %s PRIVILEGE TO %s{bcolors.ENDC}" % (username, action, device_name))
                return False
            # Check if user setting a risky state
            if not self.predictor.validate_state(device_name, incoming_state, self.risky_states, self.sys_state):
                print(f"{bcolors.FAIL}[SERVER]: !!!WARNING!!! USER %s ATTEMPTED TO TRIGGER A RISKY STATE TO %s{bcolors.ENDC}" % (username, device_name))
                return False
            device = self.reg_devices[self._filter_device(device_name)]
            status = device.execute(incoming_state, self.risky_states, self.sys_state)
            if status:
                self.sys_state[device_name][incoming_state["field"]] = incoming_state["val"]
            return status

    def _check_permission(self, user, action, device_name):
        return self.permission_checker.check(self.acl, user, action, device_name)

    def _load_users(self) -> list:
        with open('./users.json', 'r') as users:
            return json.load(users)["users"]
    
    def _load_risky_states(self) -> list:
        with open('./risky_states.json', 'r') as risky_states:
            return json.load(risky_states)["states"]

    def _load_acl(self) -> dict:
        with open('./acl.json', 'r') as acl:
            return json.load(acl)

    def _filter_user(self, username):
        target_idx = -1
        for u in range(len(self.reg_users)):
            if self.reg_users[u]["username"] == username:
                target_idx = u
        return target_idx

    def _filter_device(self, device_name):
        target_idx = -1
        for u in range(len(self.reg_devices)):
            if self.reg_devices[u].name == device_name:
                target_idx = u
        return target_idx


# Check user's permission on a device
class PermissionChecker():
    @staticmethod
    def check(acl, user, action, device_name):
        try: 
            if action in acl["group"][user["group"]][device_name]:
                return True
        except:
            pass
        try:
            if action in acl["user"][user["username"]][device_name]:
                return True
        except:
            pass
        return False


# Check system state after user's command
class StatePredictor():
    @staticmethod
    def _compare(op, left, right):
        if op == ">":
            if left > right:
                return False
        elif op == "<":
            if left < right:
                return False
        elif op == "=":
            if left == right:
                return False
        return True

    def _compare_state(self, risky_state, compare_state):
        return self._compare(risky_state["op"], compare_state["val"], risky_state["val"])

    def validate_state(self, device_name, incoming_state, risky_states, sys_state):
        for s in risky_states:
            if device_name in s["objects"]:
                states = s["states"]
                flags = {k: True for k in s["objects"]}
                for obj_name in s["objects"]:
                    for object_state in states:
                        # Compare risky state with incoming state of user command.
                        if object_state["object"] == obj_name \
                            and obj_name == device_name \
                            and object_state["field"] == incoming_state["field"]:
                            result = self._compare_state(object_state, incoming_state)
                            flags[obj_name] = False if not result else flags[obj_name]

                        # Compare other device's state registered in the system is violated.
                        # e.g. Command : aircon.temp = 35
                        #      System State: disinfector.status = on
                        #      Risky State: aircon.temp > 26 & disinfector.status = on
                        elif object_state["object"] == obj_name \
                            and object_state["object"] in sys_state.keys():
                            local_state = sys_state[object_state["object"]]
                            for k, v in local_state.items():
                                if k == object_state["field"]:
                                    result = self._compare(object_state["op"], v, object_state["val"])
                                    flags[obj_name] = False if not result else flags[obj_name]
                                    
                if all([not v for v in flags.values()]):
                    return False
        
        return True


class IoTDevice():
    def __init__(self, name, server):
        self.name = name
        self.server = server
        self.state = {}
        self.predictor = StatePredictor()
    
    # Connect to server
    def register(self):
        return self.server.bind(self)

    # Disconnect from server
    def quit(self):
        return self.server.unbind(self)
    
    # Execute command from server
    def execute(self, incoming_state, risky_states, sys_state):
        # Client side validation
        status = self.predictor.validate_state(self.name, incoming_state, risky_states, sys_state)
        if status:
            self.state[incoming_state["field"]] = incoming_state["val"]
        return status


class User():
    def __init__(self, username, ip):
        self.username = username
        self.server = None
        self.public_key = None
        self.ip = ip

    # Login to server
    def connect(self, server, password, DEBUG=False, RETURN_ONLY=False):
        self.server = server
        self.public_key = self.server.init_auth(self.username)
        msg = {
            "password": password,
            "ts": get_timestamp(),
            "nonce": get_nonce()
        }
        msg = encrypt_data(json.dumps(msg), self.public_key)
        if DEBUG:
            self.server.auth(self.username, self.ip, msg)
            return {
                    "username": self.username, 
                    "ip": self.ip, 
                    "msg": msg
                }
        elif RETURN_ONLY:
            return {
                "username": self.username, 
                "ip": self.ip, 
                "msg": msg
            }
        return self.server.auth(self.username, self.ip, msg)

    # Execute command on device
    def execute(self, device, action, state = {}):
        msg = {
            "device": device,
            "action": action,
            "incoming_state": state,
            "ts": get_timestamp(),
            "nonce": get_nonce()
        }
        msg = encrypt_data(json.dumps(msg), self.public_key)
        self.server.execute(self.username, msg)


def cleaner():
    global nonces
    global ip_requests
    global sys_running
    while sys_running:
        nonces_lock.acquire()
        ip_requests_lock.acquire()

        nonces = []
        ip_requests = {}

        nonces_lock.release()
        ip_requests_lock.release()
        time.sleep(15)



if __name__ == '__main__':
    server = IoTMonitor()
    cleaner_thread = threading.Thread(target=cleaner)
    cleaner_thread.start()

    barry = User("barry", "1.1.1.1")
    john = User("john", "2.2.2.2")

    aircon = IoTDevice("aircon", server)
    disinfector = IoTDevice("disinfector", server)
    door = IoTDevice("door", server)
    window = IoTDevice("window", server)

    barry.connect(server, "test01")
    john.connect(server, "test02")
    
    aircon.register()
    disinfector.register()
    door.register()
    window.register()

    # ------------------------------
    # TEST CASE 01: GENUINE COMMAND
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG TEST CASE 01")
    print("[USER_BARRY]: SETTING AIR CON TO 26ºC")
    barry.execute("aircon", "w", {"field": "temp", "val": 26})
    print(f"{bcolors.OKGREEN}[SYSTEM]: TEST 01 COMPLETE{bcolors.ENDC}")
    print("------------------------------------------------------------")
    print()

    # ------------------------------
    # TEST CASE 02: RISKY STATE
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG TEST CASE 02")
    print("[USER_BARRY]: SETTING DISINFECTOR TO ON")
    barry.execute("disinfector", "w", {"field": "status", "val": "on"})
    print("[SYSTEM]: TEST 02 COMPLETE")
    print("------------------------------------------------------------")
    print()

    # ------------------------------
    # TEST CASE 03: ACCESS TO OBJECTS WITHOUT PRIVILEGE
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG TEST CASE 03")
    print("[USER_JOHN]: SETTING WINDOW TO OPEN")
    john.execute("door", "w", {"field": "status", "val": "open"})
    print("[SYSTEM]: TEST 03 COMPLETE")
    print("------------------------------------------------------------")
    print()

    # ------------------------------
    # TEST CASE 04: UNAUTHORIZED ACCESS
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG TEST CASE 04")
    print("[USER_LISA]: LOGGING IN AND SETTING DOOR TO OPEN")
    lisa = User("lisa", "3.3.3.3")
    lisa.connect(server, "test03")
    lisa.execute("door", "w", {"field": "status", "val": "open"})
    print("[SYSTEM]: TEST 04 COMPLETE")
    print("------------------------------------------------------------")
    print()




    # --------------------------------------------------------------------------------------------------
    # Attack Simulation
    #-------------------------------
    print("############################################################")
    print("#                ATTACK SIMULATION STARTED                 #")
    print("############################################################")

    # ------------------------------
    # ATTACK CASE 1: MAN-IN-THE-MIDDLE  
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG ATTACK CASE 01: MAN-IN-THE-MIDDLE")
    tom = User("tom", "10.0.0.0")
    packet = tom.connect(server, "test03", DEBUG=True)
    # Simulate the case when a packet is captured
    print(f"{bcolors.WARNING}[ATTACKER]: TRY TO SEE THE CONTENT OF THE PACKET{bcolors.ENDC}")
    print(packet["msg"])
    print(f"{bcolors.WARNING}[ATTACKER]: MESSAGE IS NOW ENCRYPTED WITH RSA :({bcolors.ENDC}")
    print("[SYSTEM]: ATTACK 01 COMPLETE")
    print("------------------------------------------------------------")

    # ------------------------------
    # ATTACK CASE 2: REPLAY ATTACK  
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG ATTACK CASE 02: REPLAY ATTACK")
    tom = User("tom", "10.0.0.0")
    packet = tom.connect(server, "test03", DEBUG=True)
    print(f"{bcolors.WARNING}[ATTACKER]: TRY TO REPLAY THE LOGIN PACKET{bcolors.ENDC}")
    server.auth(packet["username"], packet["ip"], packet["msg"])
    print(f"{bcolors.WARNING}[ATTACKER]: REPLAY FAILED :({bcolors.ENDC}")
    print("[SYSTEM]: ATTACK 02 COMPLETE")
    print("------------------------------------------------------------")


    # ------------------------------
    # ATTACK CASE 3: BRUTE FORCE PASSWORD CRACKING  
    # ------------------------------
    print("------------------------------------------------------------")
    print("[SYSTEM]: RUNNINNG ATTACK CASE 03: BRUTE FORCE CRACKING")
    print(f"{bcolors.WARNING}[ATTACKER]: SENDING LOGIN REQUEST AT HIGH RATE{bcolors.ENDC}")
    attacker = User("tom", "10.1.1.1")
    attacker_packet = attacker.connect(server, "wrong_passwd", RETURN_ONLY=True)
    for i in range(15):
        server.auth(attacker_packet["username"], attacker_packet["ip"], attacker_packet["msg"])
    print(f"{bcolors.WARNING}[ATTACKER]: IP IS BLOCKED :({bcolors.ENDC}")
    print("[SYSTEM]: ATTACK 03 COMPLETE")
    print("------------------------------------------------------------")
    
    
    print("Please wait until all processes shut down (MAX 15s).")
    print("(Or press Ctrl + C to terminate)")
    sys_running = False
    cleaner_thread.join()
