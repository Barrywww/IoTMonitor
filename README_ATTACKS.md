# Assignment 2.4 - System Prototype Part B
Name: Barry Wang

NetID: yw3752

## Description
This assignment included simulated attacks and fixes to IoTMonitor.

## File Structure
```
.
├── README.md             # README file of project
├── acl.json              # Defines the Access Control List
├── main.py               # Entry of IoTMonitor & test cases
├── risky_states.json     # Defines risky states for dynamic prediction
└── users.json            # Defines the users that have access to the system
```

## How To Execute ?
```
pip install -r requirements.txt
python main.py
```

## Attack Analysis

### Attack 1. Man-In-The-Middle
In the previous implementation of IoTMonitor, all the communication between user and server, (especially authentication) is unencrypted. A man-in-the-middle attack will easily get the username / password information of the user. To defend such case, RSA is now implemented on the communication between server and client. When user try to login, he/she will encrypt the message using the public key that server generates.

The main modification is at:
- `main.py:21-32`
- `main.py:87`
- `main.py:142`
- `main.py:313`
- `main.py:332`
- `main.py:336-349`

### Attack 2. Replay Attack
The previous implementation does not check if a request has been replayed. An attacker can easily capture the request and replay to simulate user behaviors. Now, the IoTMonitor enables timestamp and nonce verification between user-server communication. To save time in testing, the interval for a message to remain valid is `15` seconds. And a new thread is added to clear the nonce storage every `secs`.

The main modification is at:
- `main.py:28-35`
- `main.py:89-96`
- `main.py:145-152`
- `main.py:310-311`
- `main.py:329-330`
- `main.py:336-349`

### Attack 3. Brute Force Password Cracking
Even though the attackers cannot try to capture the traffic of the user to get the password, yet they can fall back to running a dictionary against user's password. To increase the cost of cracking, the server will now block requests from the same ip if there are more than login `10` requests in `15` seconds. (Again, parameters only for testing purposes).

The main modification is at:
- `main.py:79-85`
- `main.py:336-349`


## Sample Output
```
############################################################
#                ATTACK SIMULATION STARTED                 #
############################################################
------------------------------------------------------------
[SYSTEM]: RUNNINNG ATTACK CASE 01: MAN-IN-THE-MIDDLE
[SERVER]: User tom connected to SERVER.
[ATTACKER]: TRY TO SEE THE CONTENT OF THE PACKET
b'/\xae\xd04\x82\xd32B\xf0\x98-5\xe0/\x8e\xcbm\xde\xfc\x04\x839\x05F>\x97_\xf7\xaas\t\xc3\x87\x85},O\x02\xcb\xee\x1cG\xc7YJmJ\x9e*\x84\x01\xf2X6\xb9\x7f\xe7\xc3\x04\xbe\xce\x10xd\xf9\x02\x85\xda\n\xed9\xc7\xab\x87\xe8\xd50\x14\xc8\x1c\x86\x88\'\xc6\xe9M\x9f}\x04\x83_q\x89\xf48i\x9eTrJ\x1c\xe5\x82\x81\x16-d\xfe\x11\x9c\xb3Y\xa1\xeb\xb6\xc0\x95z0\xae\x15L\x14\x9b\x9cK\xa8g\x89\xd1*\xec\xaeJ\xfaJ$=\xcf\xa3\'\xdc\xa2\x92 h}\x96\xa7\xcbS\x0e\xc7\x91\xaf\xc2v\x83]\xe8\xdaq\xa7\x85A\xd7\x03\x17<\x87\x99\x1c,1\xf0\x0e"\xe3%N\xfa;4\x9aT9;\xf6\xbd\x8d`\xdf\xae\x9b\xa9\x80\x07\xfc\x03L7Y\xdbw\xea\x00\x0e\xbf)\x7fZ\xe9\x1f\x9cDP\x92T\xcb\xa4\t\xab\xdc\x84\xb7\xfax\x165\xc2=3\xcf\xd0\x19\xc2u\xa0\xe5\xf9\x98\x1a\xf9\xad\xdf\x07_\x07{\xdb\x16=m]\xdd\xdb'
[ATTACKER]: MESSAGE IS NOW ENCRYPTED WITH RSA :(
[SYSTEM]: ATTACK 01 COMPLETE
------------------------------------------------------------
------------------------------------------------------------
[SYSTEM]: RUNNINNG ATTACK CASE 02: REPLAY ATTACK
[SERVER]: User tom connected to SERVER.
[ATTACKER]: TRY TO REPLAY THE LOGIN PACKET
[SERVER]: !!!WARNING!!! RECEIVED REPEATED MESSAGE FROM USER tom (POSSIBLY REPLAY).
[ATTACKER]: REPLAY FAILED :(
[SYSTEM]: ATTACK 02 COMPLETE
------------------------------------------------------------
------------------------------------------------------------
[SYSTEM]: RUNNINNG ATTACK CASE 03: BRUTE FORCE CRACKING
[ATTACKER]: SENDING LOGIN REQUEST AT HIGH RATE
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! USER tom: WRONG USERNAME OR PASSWORD.
[SERVER]: !!!WARNING!!! REQUEST FROM IP 10.1.1.1 IS TOO FREQUENT. ACCESS DENIED.
[SERVER]: !!!WARNING!!! REQUEST FROM IP 10.1.1.1 IS TOO FREQUENT. ACCESS DENIED.
[SERVER]: !!!WARNING!!! REQUEST FROM IP 10.1.1.1 IS TOO FREQUENT. ACCESS DENIED.
[SERVER]: !!!WARNING!!! REQUEST FROM IP 10.1.1.1 IS TOO FREQUENT. ACCESS DENIED.
[ATTACKER]: IP IS BLOCKED :(
[SYSTEM]: ATTACK 03 COMPLETE
------------------------------------------------------------
```