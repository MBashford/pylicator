# Pylicator #
A SNMP trap exploder/forwarder implemented in python

## Getting Pylicator ##
Pylicator requires Python 3.8 or above. Whatever method used to get Pylicator, it is recommended to run it from a python virtual environment. Start by creating and navigting into a directory for the project with `mkdir Pylicator` & `cd Pylicator`.

Then create a python virtual environment named pylicatorVenv within the directory using:  

`python -m venv pylicatorVenv`  

And activate the virtual environment using:  

`source pylicatorVenv/bin/activate`

Now install Pylicator using one of the below methods

### Install using PIP ###
To install the latest stable version usig pip:  
`pip install git+https://github.com/MBashford/pylicator.git`

### Cloning the git repo ###
Alternatively, clone the git repo with:  
`git clone https://github.com/MBashford/pylicator.git`

Cloning the repo will require dependencies to be installed separately. Do this manually or by running `python setup.py install` from the pylicator root directory.

## Configuration ##
Once installed locate the config file, **pylicator.conf**, in the pylicator root directory. If installed via pip, this location can be found with:  
`pip show pylicator`

If there is no **pylicator.conf** file in this directory, running pylicator with `python pylicator.py` will cause it to generate a sample config file in the pylicator root directory and exit.

It is also possible to have pylicator search for a config file outside of its' root directory by passing a file or directory path using either `python pylicator.py -c <path-to-config-file>` or `python pylicator.py --conf-path <path-to-config-file>`. Pylicator will attempt to generate a config file at this location if one is not found.

The config file contains the following sections:

### Settings ###
Contains options specifying the listen port and logging behaviour. 

Option | Description
-- | --
listen_port | the port pylicator will listen on for incoming SNMP traps, default is port 162.
log_path | path to the pylicator log file or directory, the directory must already exist. If no file name is specified the default name `pylicator.log` will be used. Leaving this seting blank will cause logs to be written in the pylicator root directory.
log_data_path | path to the pylicator trap logs file or directory, the directory must already exist. If no file name is specified the default name `pylicator-data.log` will be used. Leaving this setting blank will cause trap logs to be written in the pylicator root directory. If this is set to the same value as log_path, both logs and traps will be written to one file.
log_traps | if pylicator will attempt to parse and log the contents of recieved traps using the included naive asn1 decoder. Only contents of SNMPv1 and SNMPv2c traps will be parsed.
log_bytes | if the recived traps will be logged as bytes in addition to the parsed contents. Requires trap logging to be enabled.
spoof_src* | determines the source address to use on forwarded packets. True: use ip received with traps, False: use pylicator host ip

*Note ip spoofing not supported on some windows versions, setting this to True may cause traps to be lost

Pylicator must be restarted for settings changes to take effect.

### Forwarding Rules ###
Defines forwarding behaviour for traps recieved from different IPv4 addresses. Multiple forwarding destinations can be assigned to each origin. Rules are defined as key-value pairs with the stucture 
"\<origin\> = \<destination 1\> \<destination 2\>". At present only IPv4 addresses are accepted. Below are some valid example rules:  
```
58.113.42.112 = 86.34.127.50:162
0.0.0.0/0 = 172.0.0.1:162 192.168.1.86:162
172.0.0.1/32 = 172.0.0.1:5432 192.168.0.1
```

If no destination port is specified in a rule, port 162 will be used by default.


## Running Pylicator ##
This is as simple as calling `python pylicator.py`, however for reliability it is recommended to add pylicator as a service. The sample service file for linux systems **pylicator.service** can be found in the pylicator install directory or in the git repo. 

### Running as a Service in Linux ###
First, ensure that pylicator.py is set as an executable using `chmod +x pylicator.py`, then locate and open the sample **pylicator.service** file.
```
WorkingDirectory = <path-to-pylicator-root-directory>  
ExecStart = <path-to-pylicator-root-directory>/pylicator.py
```

Edit the above fields  in the service file to point at the directory containing pylicator.py, then copy **pylicator.service** to the `/etc/systemd/system` directory. If running Pylicator from a virtual envionment set the 'ExecStart' option as:

`ExecStart = <path-to-virtual-env>/bin/python <path-to-pylicator-root-directory>/pylicator.py`  

For deployment in production environments it is also recommended to set `Restart=always` so that the pylicator service will restart should it exit unexpectedly. Below is an example service file showing Pylicator buing run using a virtual environment located in `/etc/pylicatorVenv` and a config file located outside of the working directory in `/var/configs`   

```
#
# /etc/systemd/system/pylicator.service
#

[Unit]
Description=Pylicator: Redirects incoming SNMP traps
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/pylicator/
ExecStart=/etc/pylicatorVenv/bin/python /etc/pylicator/pylicator.py --conf-path /var/configs/pylicator.conf
Restart=no

[Install]
WantedBy=multi-user.target
```

Execute `systemctl daemon-reload` to reload the systemd configuration, you should then be able to start and stop the pylicator service with `systemctl start pylicator.service` and `systemctl stop pylicator.service`. Use `systemctl status pylicator.service` to verify that pylicator is running correctly. Set Pylicator to start on system boot with `systemctl enable pylicator.service`.

## Planned Featues ##
- Optional load-balancing for traps forwarded to multiple destinations
- Track metrics for recieved traps, frequency by origin subnet, destination, etc.

## Contributors ##
- Milo Bashford (<milo.bashford@gmail.com>)

## License ##
Pylicator is free software that is made available under the MIT license.

