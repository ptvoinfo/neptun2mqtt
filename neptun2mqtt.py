#!/usr/bin/python
# -*- coding: utf-8 -*-

from neptun import *
import os
import signal
import paho.mqtt.client as mqtt
import json
import sys, traceback
import time
import datetime
import binascii
import logging
import traceback

import configparser as ConfigParser  # Python 3+
import _thread as thread

devices = None

exitSignal = False
debug_mode = 0
logger = None
mqtt_client = None
MQTT_QOS = 0
MQTT_RETAIN = False
MQTT_PATH = 'neptun/{friendly_name}'
connected_devices_info = {}
connected_devices = {}
subscribed_devices = {} # maintain this list independently because MQTT client may connect/disconnect

def signal_handler(signal, frame):
    """
    Captures the "Ctrl+C" event in a console window and signals to exit
    """
    log('SIGINT')
    global exitSignal
    exitSignal = True


def printf(*args):
    together = ' '.join(map(str, args))    # avoid the arg is not str
    return together


def log(*args):
    if logger is not None:
        logger.info(printf(*args))
    else:
        d = datetime.datetime.now()
        print(d.strftime("%Y-%m-%d %H:%M:%S"), *args)
    return


def log_traceback(message, ex, ex_traceback=None):
    """
    Log detailed call stack for exceptions.
    """
    if ex_traceback is None:
        ex_traceback = ex.__traceback__
    tb_lines = [line.rstrip('\n') for line in
                traceback.format_exception(ex.__class__, ex, ex_traceback)]
    log(message + ':', tb_lines)

def on_connect(client, userdata, flags, rc):
    """
    The callback for when the client receives a CONNACK response from the server.
    """
    log("Connected with result code:", rc)
    subscribed_devices = {} # we (re)subscribe when data will be received

def str_to_bool(value):
    data = str(value)
    if (data == '1') or (data == 'True'):
        return True
    else:
        return False

def on_message(client, userdata, msg):
    """
    The callback for when a PUBLISH message is received from the server.
    path_to_command/command - receives a json encoded command and allows you to change the valve and cleaning mode states at the same time
    path_to_command/command/valve - receives 0/1 or False/True and allows you to change the valve state individually
    path_to_command/command/cleaning - receives 0/1 or False/True and allows you to change the cleaning mode  state
    """
    if msg is None or msg.payload is None:
        return

    log("Topic:", msg.topic, "\nMessage:", msg.payload)
    parts = msg.topic.split('/')
    last = parts.pop(-1)
    msg_topic = None

    valve_state_open = None
    flag_dry = None

    if last == 'command':
        # json command
        msg_topic = msg.topic
        try:
            data = json.loads(msg.payload)
            if 'cleaning' in data:
                flag_dry = str_to_bool(data['cleaning'])
            if 'valve' in data:
                valve_state_open = str_to_bool(data['valve'])
        except:
            log('Invalid JSON data:', msg.payload)
            return
    elif (last == 'valve') or (last == 'cleaning'):
        msg_data = msg.payload.decode("utf-8")

        parts.pop(-1) # remove 'command'
        msg_topic = '/'.join(parts)
        if last == 'valve':
            valve_state_open = str_to_bool(msg_data)
        if last == 'cleaning':
            flag_dry = str_to_bool(msg_data)            
    else:
        return

    """
    we can serve several devices
    trying to find a device by the topic name
    """
    found = None
    for ip, topic in subscribed_devices.items():
        if topic ==  msg_topic:
            found = ip
            break

    if (found is None) or (found not in connected_devices):
        log('Unable to execute command. Device not found')
        return

    connector = connected_devices[found]

    if 'line_in_config' not in connector.device:
        # connector not ready yet
        log('Unable to execute command. Device not ready yet')
        return

    if valve_state_open is None:
        valve_state_open = connector.device['valve_state_open']
    else:
        connector.device['valve_state_open'] = valve_state_open
    if flag_dry is None:
        flag_dry = connector.device['flag_dry']
    else:
        connector.device['flag_dry'] = flag_dry

    flag_cl_valve = connector.device['flag_cl_valve']
    line_in_config = connector.device['line_in_config']

    log('Sending command to the device: Valve:', valve_state_open, 'Cleaning:', flag_dry)
    connector.send_settings(valve_state_open, flag_dry, flag_cl_valve, line_in_config)
    connector.command_signal = 1 # re-read device state after the command
    return True

def prepare_mqtt(MQTT_SERVER, MQTT_PORT=1883):
    """
    Prepare and connect to a MQTT server.
    """
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_SERVER, MQTT_PORT, 60)
    return client


def push_data(client, path, data):
    """
    Publish prepared data on the server.
    """

    if client is None:
        return

    client.publish(path, payload=str(data), qos=MQTT_QOS, retain=MQTT_RETAIN)


def ConfigSectionMap(Config, section):
    """
    Load settings from a INI file section to a dict.
    """
    dict1 = {}
    options = Config.options(section)
    for option in options:
        if option.startswith(';'):
            pass
        else:
            try:
                dict1[option] = Config.get(section, option)
                if dict1[option] == -1:
                    log("skip: %s" % option)
            except:
                log("Exception on %s!" % option)
                dict1[option] = None
    return dict1

def get_device_topic(ip):
    """
    Make a device topic name string from a template.
    """
    info = connected_devices_info.get(ip)
    if info is not None:
        friendly_name = info.get('friendly_name', '')
        if friendly_name == '':
            friendly_name = info.get('name', '')
        path = MQTT_PATH.format(
            friendly_name=friendly_name,
            ip=ip,
            name=info.get('name', ''))
        return path
    return None

def check_subscription(ip):
    """
    Check subscription for a device topic name.
    """
    if ip in subscribed_devices:
        return

    if mqtt_client is not None:
        path = get_device_topic(ip)
        if path is None:
            # device is not connected yet
            return
        _error = "Unable to subscribe"
        try:
            path1 = path + "/command/+"
            log("Subscribing to:", path1)
            mqtt_client.subscribe(path1)
            path2 = path + "/command"
            log("Subscribing to:", path2)
            mqtt_client.subscribe(path2)
            subscribed_devices[ip] = path
        except Exception as e:
            log_traceback(_error, e)
        except:
            log(_error)

def prepare_and_publish_value(path, data, value, topic):
    if value in data: 
        if data[value]:
            str_value = '1'
        else:
            str_value = '0'    
        push_data(mqtt_client, path + '/' + topic, str_value)

def prepare_and_publish_data(connector):
    """
    Prepare device data for publishing.
    """
    #log('Device info:', connector.device)

    # select data to publish
    names = ('timestamp', 'name', 'mac', 'ip', 'status', 'status_name', 'valve_state_open', 'flag_dry')
    lines2 = dict(connector.device['lines'])
    for line_id in lines2:
        line_info = lines2[line_id]
        name = line_info.get('name', '')
        if name == '':
            del lines2[line_id]
    data2 = {}
    for name in names:
        if name in connector.device:
            data2[name] = connector.device[name]
    data2['lines'] = lines2

    data_plain = json.dumps(data2)#.encode("utf-8")

    path = get_device_topic(ip)
    log('publishing data', data_plain)
    push_data(mqtt_client, path, data_plain)

    prepare_and_publish_value(path, data2, 'valve_state_open', 'valve')
    prepare_and_publish_value(path, data2, 'flag_dry', 'cleaning')

    return

def callback_data(connector, sock, ip, data):
    """
    The callback for connectors that read data from devices.
    """
    _error = "Unable to process data"
    try:
        check_subscription(ip)

        if data['type'] == PACKET_SENSOR_STATE:
            connector.can_send_background_status_request = True
            connected_devices_info[ip].update(connector.device)
            return prepare_and_publish_data(connector)

        elif data['type'] == PACKET_BACK_STATE:
            return prepare_and_publish_data(connector)

        elif data['type'] == PACKET_SET_SYSTEM_STATE:
            if connector.command_signal == 1:
                connector.command_signal = 0
                connector.send_get_system_state()
    except Exception as e:
        log_traceback(_error, e)
    except:
        log(_error)            

    return


def connect_device(ip, device_info, silent):
    """
    Add a device to a list of monitored devices.
    """
    check_subscription(ip)

    if ip not in connected_devices:
        if not silent:
            log('New device found:', ip)

        connected_devices_info[ip] = device_info

        connector = NeptunConnector(ip,
                                    data_callback=callback_data,
                                    log_callback=log,
                                    debug_mode=debug_mode)

        connected_devices[ip] = connector

        connector.setDaemon(True)
        connector.whois_request.last_sent = datetime.datetime.now()
        connector.start()

        connector.system_state_request = RequestSendPeriodically(connector, 120, connector.send_get_system_state)
        connector.system_state_request.last_sent = datetime.datetime.now()
        connector.send_get_system_state()

        connector.can_send_background_status_request = False
        connector.background_status_request = RequestSendPeriodically(connector, 30, connector.send_get_background_status)

        return connector
    return connected_devices[ip]


def callback_discovery(connector, sock, ip, data):
    """
    The callback for auto discovery connector.
    """
    connect_device(ip, data, False)

    connector = connected_devices[ip]

    if not connector.socket.wait_response:
        if time_delta(connector.last_state_updated) > connector.state_update_interval:
            connector.send_get_system_state()
    return

if __name__ == "__main__":
    Config = ConfigParser.ConfigParser()

    script_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), '')
    script_name = os.path.basename(__file__)
    script_ini = script_path + os.path.splitext(script_name)[0]+'.ini'

    log('Read settings from:', script_ini)
    Config.read(script_ini)

    mqtt_cfg = ConfigSectionMap(Config, "MQTT")
    debug_mode = int(mqtt_cfg.get('debug', 0))

    log_file = mqtt_cfg.get('log', '')
    if log_file != '':
        if (debug_mode > 1) and os.path.isfile(log_file):
            os.remove(log_file)
        logger = logging.getLogger('mihome')
        hdlr = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logger.setLevel(logging.INFO)

    MQTT_QOS = int(mqtt_cfg.get('qos', 0))
    tmp = int(mqtt_cfg.get('retain', 0))
    if tmp > 0:
        MQTT_RETAIN = True
    else:
        MQTT_RETAIN = False
    MQTT_SERVER = mqtt_cfg['server']
    MQTT_PORT = int(mqtt_cfg['port'])
    MQTT_PATH = mqtt_cfg.get('mqtt_path', 'neptun/{friendly_name}')

    devices_cfg = ConfigSectionMap(Config, "devices")
    auto_discovery = int(devices_cfg.get('discovery', '1'))
    devices_str = devices_cfg['devices']
    if not sys.version_info >= (3, 0):
        devices_str = devices_str.decode('utf-8')

    devices = json.loads(devices_str)

    #mqtt_client = None
    mqtt_client = prepare_mqtt(MQTT_SERVER, MQTT_PORT)

    discovery_connector = None
    if auto_discovery == 1:
        discovery_connector = NeptunConnector(BROADCAST_ADDRESS,
                                              data_callback=callback_discovery,
                                              log_callback=log,
                                              debug_mode=debug_mode)
        discovery_connector.setDaemon(True)
        discovery_connector.start()

    for device_info in devices:
        connector = connect_device(device_info['ip'], device_info, True)
        if connector is not None:
            connector.state_update_interval = device_info.get('interval', 120)

    _error = "Unable to start thread"
    try:
        if mqtt_client is not None:
            thread.start_new_thread(mqtt_client.loop_forever, ())
    except Exception as e:
        log_traceback(_error, e)
    except:
        log(_error)

    log("Starting main thread")
    signal.signal(signal.SIGINT, signal_handler)

    _error = "Error in main thread"
    while not exitSignal:
        try:
            if discovery_connector is not None:
                if discovery_connector.whois_request.count < 2:
                    discovery_connector.whois_request.check_send(5)
                else:
                    discovery_connector.whois_request.check_send(1800, False)

            for ip in connected_devices:
                connector = connected_devices[ip]
                if not connector.system_state_request.check_send(connector.state_update_interval, False):
                    if connector.can_send_background_status_request:
                        connector.background_status_request.check_send(30, False)

            time.sleep(0.5)
        except Exception as e:
            log_traceback(_error, e)
        except:
            log(_error)

    if discovery_connector is not None:
        log("Stopping discovery connector")
        discovery_connector.terminate()

    for ip in connected_devices:
        log("Stopping connector for", ip)
        connector = connected_devices[ip]
        connector.terminate()

    log("Exit")
