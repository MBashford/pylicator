# Pylicator #
A SNMP trap exploder/forwarder implemented in python

## Getting Pylicator ##
Whatever method used to get Pylicator, it is recommended to run it from a python virtual environment. Start by creating and navigting into a directory for the project with `mkdir Pylicator` & `cd Pylicator`.

Then create a python virtual environment named pylicatorVenv within the directory using:  

`python -m venv pylicatorVenv`  

And activate the virtual environment using:  

`source pylicatorVenv/bin/activate`

Now install Pylicator using one of the below methods

### Install using PIP ###
To install the latest stable version usig pip:  
`pip install pip@git+https://github.com/MBashford/pylicator.git`

### Cloning the git repo ###
Alternatively, clone the git repo with:  
`git clone https://github.com/MBashford/pylicator.git`

Cloning the repo will require dependencies to be installed separately. Do this manually or by running `python setup.py install` from the pylicator root directory.

## Configuration ##
Once installed locate the config file, **pylicator.conf**, in the pylicator root directory. If installed via pip, this location can be found with:  
`pip show pylicator`

If there is no **pylicator.conf** file in this directory, running pylicator with `python pylicator.py` will cause it to start with the with the default settings and generate a new config file in the pylicator root directory.

The config file contains the following sections:

### Settings ###
Contains options specifying the listen port and logging behaviour. 

Option | Description
-- | --
listen_port | the port pylicator will listen on for incoming SNMP traps, default is port 162.
log_path | path to the directory containig log files, leaving blank will cause logs to be written in the pylicator root directory.
log_traps | if pylicator will attempt to parse and log the contents of recieved traps using the included naive asn1 decoder.
log_bytes | if the recived traps will be logged as bytes in addition to the parsed contents. Requires trap logging to be enabled.


### Forwarding Rules ###
Defines forwarding behaviour for traps recieved from different IPv4 addresses. Multiple forwarding destinations can be assigned to each origin. Rules are defined as key-value pairs with the stucture 
"\<origin\> = \<destination 1\> \<destination 2\>". At present only IPv4 addresses are accepted and port numbers must be specified as part of the destination address. Below are some valid example rules:  
```
58.113.42.112 = 86.34.127.50:162
0.0.0.0/0 = 172.0.0.1:162 192.168.1.86:162
172.0.0.1/32 = 172.0.0.1:5432 192.168.0.1:4321
```

## Running Pylicator ##
This is as simple as calling `python pylicator.py`, however for reliability it is recommended to add pylicator as a service. The sample service file for linux systems **pylicator.service** can be found in the pylicator install directory or in the git repo. 

### Running as a Service in Linux ###
First, ensure that pylicator.py is set as an executable using `chmod +x pylicator.py`, then locate and open the sample **pylicator.service** file.
```
WorkingDirectory = <path-to-pylicator-root-directory>  
ExecStart = <path-to-pylicator-root-directory>/pylicator.py
```

Edit the above fields  in the service file to point at the directory containing pylicator.py, then copy **pylicator.service** to the `/etc/systemd/system` directory. If running Pylicator from a virtual envionment set the 'ExecStart' option as:

`ExecStart = <path-to-pylicatorVenv>/bin/python <path-to-pylicator-root-directory>/pylicator.py`  

For deployment in production environments it is also recommended to set `Restart=always` so that the pylicator service will start on system reboot. 

Execute `systemctl daemon-reload` to reload the systemd configuration, you should then be able to start and stop the pylicator service with `systemctl start pylicator.service` and `systemctl stop pylicator.service`. Use `systemctl status pylicator.service` to verify that pylicator is running correctly.


## Contributors ##
- Milo Bashford (<milo.bashford@gmail.com>)

## License ##
Pylicator is free software that is made available under the MIT license.

