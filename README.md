# Neptun ProW+ - MQTT bridge

This script allows you to read data and control state of water leak detection system "[Neptun ProW+](https://neptun-mcs.ru/catalog/filter/c1/p4/v2/)".

The system controls one or more wire or wireless sensors and closes a valve when a water leak is detected.

You can:

* Control one or more devices
* Get state of the main module and all sensors
* Open or close a valve
* Enable or disable the special "Cleaning" mode

## How to configure

The "neptun2mqtt.ini" file in the program folder contains all settings:

### MQTT
**debug** - debug mode (0..2)

**log** - log file location

**server** - MQTT server IP address

**port** - MQTT server IP port

**username** / password - login and password for the MQTT server

**mqtt_path** - a base topic for each device.

**qos** - default QoS for all published data

**retain** - default "Retain" flag for all published data

### Devices

**discovery** - 1: enable auto-discovery of device in your local network (if the IP address of the device is dynamic)

**devices** - the "devices" parameter allows you to specify one or more devices with a static IP address and its friendly name.

```
devices = [
              {"ip": "192.168.1.92", "friendly_name": "Neptun"}
         ]
```

## How to install on Raspberry Pi or Banana Pi

```bash
$ sudo su
$ pip3 freeze --local | grep -v '^\-e' | cut -d = -f 1  | xargs -n1 pip3 install -U
$ pip3 install ConfigParser paho-mqtt
$ chmod 0755 neptun2mqtt.sh
$ cp neptun2mqtt.sh /etc/init.d
$ update-rc.d neptun2mqtt.sh defaults
$ service neptun2mqtt start
```

## How to start/stop the daemon

$ sudo service neptun2mqtt start

https://github.com/ptvoinfo/neptun2mqtt
