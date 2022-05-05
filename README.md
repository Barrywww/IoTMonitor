# Assignment 2.3 - System Prototype Part A
Name: Barry Wang

NetID: yw3752

## Description
This is a prototype of IoTMonitor, implemented and tested in Python. 

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
python3 main.py
```

## System Architecture
Subject: `Users`

Object: `IoTMonitor`, `IoTDevice`

Reference Monitor: `StatePredictor`, `PermissionChecker`