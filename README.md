# PayShieldToSyslog

<a href="https://www.jetbrains.com/?from=payShiled2Syslog"><img src=images/jetbrains-variant-3.png width=100></a>
Many thanks to <a href="https://www.jetbrains.com/?from=PayshieldPPressureTest">JetBrains</a> for giving us the <b>Open
Source License</b> for free with the full access to their developer suite until September 2022.
<a href="https://www.jetbrains.com/pycharm/?from=payShiled2Syslog">PyCharm</a> is an awesome Python IDE that
greatly simplified my work.

<img src=images/supporting-member-badge.png width=100>

The aim of **payShield2Syslog** project is to gather the Audit log via the host command **Q2**, interpreter
the response of the appliance and eventually send it to a syslog facility.

It requires **Python 3**. It was tested on **Python 3.10**

## Version


**0.4.2**


## Usage

    usage: payShieldToSyslog.py [-h] [--port PORT] [--header HEADER] [--allentries] [--decode] [--times TIMES]
                                [--proto {tcp,udp,tls}] [--keyfile KEYFILE] [--crtfile CRTFILE] [--syslog SYSLOG]
                                [--syslogport SYSLOGPORT] [--syslogproto {udp,tcp}] host

### Mandatory parameter(s)

**host** *ip address* or the *hostname/fqdn* of the **payShield** host port.

### Mutually exclusive parameters

**--times** and **--allentries** are mutually exclusive.

### Optional parameters

**--port** specifies the host port, if omitted the default value **1500** is used.

**--proto** specifies the protocol to use, **tcp**, **udp** or **tls**, if omitted the default value is **tcp**
is used.  

If **tls** is used you might specify the path of the client key file and the certificate using the parameters **--keyfile** and **--crtfile**.

**--keyfile** the path of the client key file, if is not specified the default value is **client.key**.  
It's only considered if the protocol is **tls**.

**--crtfile** the path of the client certificate file, if is not specified the default value is **client.crt**.  
It's only considered if the protocol is **tls**.

**--header** the header string to prefix to the host command, if not specified the default value is **HEAD**.

**--allentries** when specified all log entries are retrieved. In case of errors it terminates. Use **CTRL-C** to terminate it prematurely.

**--times** how many times execute the test. If it is not specified the default value is **1** time.

**--decode** decodes the response of the payShield and, if a syslog facility is specified the message is sent to syslog.

**--syslog** *ip address* or the *hostname/fqdn* of the address of the syslog facility.

**--syslogport** The syslog port. If not specified the port is **514**.

**--syslogproto** It can be **tcp** or **udp**. If not specified the default is **udp**.

## Example

    C:>python.exe payShieldToSyslog.py 192.168.0.36 --decode 
    PayShield Audit Log utility, version 0.4.2, by Marco S. Zuppone - msz@msz.eu - https://msz.eu
    To get more info about the usage invoke it with the -h option
    This software is open source and it is under the Affero AGPL 3.0 license
    
    Iteration:  1  of  1
    
    Return code: 00 No error
    Command sent/received: Q2 ==> Q3
    sent data (ASCII) : HEADQ2
    sent data (HEX) : 0006484541445132
    received data (ASCII): HEADQ3000000008E1228421409224F4ED0003030E33E14B46D6AE2270C57CD515A4C1BBF79ECAFAA60361A7D
    received data (HEX) : 005848454144513330303030303030303845313232383432313430393232344634454430303033303330453333453134423436443641453232373043353743443531354134433142424637394543414641413630333631413744
    
    -----DECODING RESPONSE-----
    Message length:  88
    Header:  HEAD
    Command returned:  Q3
    Error returned:  00
    Log Entry in Hex:  0000008E1228421409224F4ED0003030E33E14B46D6AE2270C57CD515A4C1BBF79ECAFAA60361A7D
    Audit Counter:  142
    Date:  12:28:42 14/09/2022
    Action Code ON
    Bit Mask 1101000000000000
        Command code type: User Action
        Not Archived
        Retrieved
        Unused: 000000000000
    Response Error Code: 00
    Audit Record MAC: E33E14B46D6AE227
    Random MAC Key: 0C57CD515A4C1BBF79ECAFAA60361A7D
    
    DONE

## NOTES

- The project is still in development stage and not all the functionalities are fully tested.
- For testing the Syslog functionality I used Kiwi Syslog on Windows 10 and worked fine.
- The messages are sent to syslog only if the parameter **--decode** is used.
- The entry that is sent to syslog has the following format:
  - Audit Counter
  - Date and time
  - Action or Command Code
  - Command code type:
    - **HOST**: Host command
    - **CONS**: Console command
    - **FRD**:  Fraud
    - **USER**: User Action
  - Record archive status:
    - **NOTA**: Not Archived
    - **ARCH**: Archived
  - Record retrieve status:
    - **RETR**: Retrieved
    - **NOTR**: Not Retrieved
  - Audit Record MAC
  - Random MAC Key
- **Example**: 78 10:40:43 15/09/2022 73 USER NOTA RETV 48E98471284E57B9 1C7C62DC485953F912380B446566E211

## COPYRIGHT & LICENSE
  Please refer to the **LICENSE** file that is part of this project.
  The license is **[AGPL 3.0](https://www.gnu.org/licenses/agpl-3.0.en.html)**
  
  Copyright(C) 2023 **Marco S. Zuppone** - **msz@msz.eu** - [https://msz.eu](https://msz.eu)

This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU Affero General Public License as  
published by the Free Software Foundation, either version 3 of the  
License, or any later version.

This program is distributed in the hope that it will be useful,  
but **WITHOUT ANY WARRANTY; without even the implied warranty of  
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.** See the  
**GNU Affero General Public License** for more details.

## Questions, bugs & suggestions
For any questions, feedback, suggestions, send money ***(yes...it's a dream, I know)*** you can contact the author at [msz@msz.eu](mailto:msz@msz.eu).
