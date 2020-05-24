import os
import math
import sqlite3
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
import pyshark

import statistic
from sql import insert_statistic, insert_file

DISPLAY_FILTERS = 'http or tcp or udp or tls or dns and !mdns'
STATIC_DIR = 'static'
SQLITE_PATH = 'sqlitedb.db'
TIMEOUT = 10


def capture_traffic(timeout=None, interface='en0'):
    capture = pyshark.LiveCapture(interface, display_filter=DISPLAY_FILTERS)
    capture.sniff(timeout=timeout)
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


def get_protocol_count(df):
    """
    Количество запросов для каждого протокола
    """
    df_protocol = df.groupby('Protocol').Source.count()
    df_protocol.sort_values(ascending=False)
    return df_protocol


def get_protocol_size(df):
    """
    Общий размер данных для каждого протокола
    """
    df_sum_length = df.groupby('Protocol').Length.sum()
    df_sum_length_mb = statistic.get_mb_from_b(df_sum_length)
    df_sum_length_mb.sort_values(ascending=False)
    return df_sum_length_mb


def get_mean_size_packet(df_size, df_count):
    """
    Средний размер пакета для протокола
    """
    return df_size / df_count


def save_plot(df):
    plot = df.plot(kind='bar', color=plt.cm.Paired(np.arange(len(df))))
    fig = plot.get_figure()
    filename = '{}.png'.format(datetime.strftime(datetime.now(), '%Y-%m-%d_%H:%M:%S:%f'))
    filepath = os.path.join(STATIC_DIR, filename)
    fig.savefig(filepath)
    return filename


if __name__ == '__main__':
    conn = sqlite3.connect(SQLITE_PATH)
    while True:
        capture = capture_traffic(TIMEOUT)
        packets = capture._packets
        mean = statistic.calculate_mean(packets)
        dispersion = statistic.calculate_dispersion(packets, mean)
        standard_deviation = math.sqrt(dispersion)

        cursor = insert_statistic(
            conn,
            (
                statistic.get_mb_from_b(mean),
                statistic.get_mb_from_b(dispersion),
                statistic.get_mb_from_b(standard_deviation),
            )
        )
        statistic_id = cursor.lastrowid

        data = format_packets(packets)
        df = pd.DataFrame(data=data)
        protocol_size = get_protocol_size(df)
        protocol_count = get_protocol_count(df)
        mean_size_packet = get_mean_size_packet(protocol_size, protocol_count)
        filepaths = (
            save_plot(protocol_size),
            save_plot(protocol_count),
            save_plot(mean_size_packet),
        )

        for filepath in filepaths:
            insert_file(conn, (statistic_id, filepath))
