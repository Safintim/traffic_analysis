import math
import sqlite3

import RPi.GPIO as gpio
import pandas as pd
import pyshark

import statistic
from sql import insert_statistic, insert_file

DISPLAY_FILTERS = 'http or tcp or udp or tls or dns and !mdns'
STATIC_DIR = 'static'
SQLITE_PATH = 'sqlitedb.db'
PACKET_COUNT = 25000


def capture_traffic(packet_count, interface='en0'):
    capture = pyshark.LiveCapture(interface, display_filter=DISPLAY_FILTERS)
    capture.sniff(packet_count=packet_count)
    return capture


def format_packets(packets):
    data = {
        'Source': [],
        'Destination': [],
        'Protocol': [],
        'Length': []
    }

    for packet in packets:
        try:
            data['Source'].append(packet.ip.src)
            data['Destination'].append(packet.ip.dst)
            data['Protocol'].append(packet.transport_layer)
            data['Length'].append(int(packet.length))
        except AttributeError:
            print(packet)

    return data


def setup_gpio():
    gpio.setup(10, gpio.OUT)
    gpio.setup(12, gpio.OUT)
    gpio.setup(13, gpio.OUT)
    gpio.setup(14, gpio.OUT)
    gpio.setup(15, gpio.OUT)
    gpio.setup(16, gpio.OUT)
    gpio.setup(17, gpio.OUT)
    gpio.setup(18, gpio.OUT)
    gpio.setup(19, gpio.OUT)
    gpio.setup(21, gpio.OUT)
    gpio.setup(24, gpio.OUT)
    gpio.setup(26, gpio.OUT)


def on_sun():
    gpio.setup(13, gpio.HIGH)
    gpio.setup(19, gpio.HIGH)
    gpio.setup(16, gpio.HIGH)


def off_sun():
    gpio.setup(13, gpio.LOW)
    gpio.setup(19, gpio.LOW)
    gpio.setup(16, gpio.LOW)


def off_cloud():
    gpio.setup(10, gpio.LOW)
    gpio.setup(12, gpio.LOW)
    gpio.setup(14, gpio.LOW)
    gpio.setup(15, gpio.LOW)
    gpio.setup(17, gpio.LOW)
    gpio.setup(18, gpio.LOW)
    gpio.setup(21, gpio.LOW)
    gpio.setup(24, gpio.LOW)
    gpio.setup(26, gpio.LOW)


def on_cloud():
    gpio.setup(10, gpio.HIGH)
    gpio.setup(12, gpio.HIGH)
    gpio.setup(14, gpio.HIGH)
    gpio.setup(15, gpio.HIGH)
    gpio.setup(17, gpio.HIGH)
    gpio.setup(18, gpio.HIGH)
    gpio.setup(21, gpio.HIGH)
    gpio.setup(24, gpio.HIGH)
    gpio.setup(26, gpio.HIGH)


if __name__ == '__main__':
    gpio.setmode(gpio.BCM)
    setup_gpio()
    conn = sqlite3.connect(SQLITE_PATH)
    while True:
        capture = capture_traffic(packet_count=PACKET_COUNT)
        on_sun()
        on_cloud()
        mean = statistic.calculate_online_mean(capture)
        dispersion = statistic.calculate_online_dispersion(capture, mean)
        standard_deviation = math.sqrt(dispersion)
        off_sun()

        cursor = insert_statistic(
            conn,
            (
                statistic.get_mb_from_b(mean),
                statistic.get_mb_from_b_for_dispersion(dispersion),
                statistic.get_mb_from_b(standard_deviation),
            )
        )
        statistic_id = cursor.lastrowid

        data = format_packets(iter(capture))
        df = pd.DataFrame(data=data)
        protocol_size = statistic.get_protocol_size(df)
        protocol_count = statistic.get_protocol_count(df)
        mean_size_packet = statistic.get_mean_size_packet(protocol_size, protocol_count)
        filepaths = (
            statistic.save_plot(
                protocol_size,
                title='Общий размер пакетов сгруппированных по протоколам',
                xlabel='Protocol',
                ylabel='Size (Mb)',
                static_dir=STATIC_DIR,
            ),
            statistic.save_plot(
                protocol_count,
                title='Количество пакетов сгруппированных по протоколам',
                xlabel='Protocol',
                ylabel='Count',
                static_dir=STATIC_DIR,
            ),
            statistic.save_plot(
                mean_size_packet,
                title='Средние размеры пакета для каждого протокола',
                xlabel='Protocol',
                ylabel='Size (bytes)',
                static_dir=STATIC_DIR,
            ),
        )

        for filepath in filepaths:
            insert_file(conn, (statistic_id, filepath))
        off_cloud()
    gpio.cleanup()
