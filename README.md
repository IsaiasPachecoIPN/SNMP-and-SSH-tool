# SNMP-and-SSH-tool

Tool developed for the network services class. This tool allows users to connect via SSH to a router and send commands, and if the SNMP protocol is configured on the router, SNMP mibs can also be received and sent.

## Technologies
* PySide6
* pysnmp
* paramiko

## Usage
- The tool must be run on a machine belonging to the same network as the router to be managed and the SSH and SNMP protocol must be enabled to achieve the connection.

- Then run the tool via "python main.py" and in the "Register" menu enter the router name, IP and password. If the connection is successful or not, a message will be displayed.

- If the connection is successful, you can type any command in the "Enter commands" box and then press "Execute" to send and execute the command on the router, the output will be shown in the "Output" box.

- The box "SNMP Traps" will be showing all the MIBs sended by the router. The menu "SNMP-GET" can be used to send some SNM get messages and test the protocol.

## ScreenShots
![A](/screenShots/snmp_1.png)

![B](/screenShots/snmp_2.png)

![C](/screenShots/snmp_2.png)
