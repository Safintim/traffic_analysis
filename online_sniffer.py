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


def save_plot(df, title, xlabel, ylabel):
    plot = df.plot(
        kind='bar',
        color=plt.cm.Paired(np.arange(len(df))),
        title=title
    )
    plot.set_xlabel(xlabel)
    plot.set_ylabel(ylabel)
    fig = plot.get_figure()
    filename = '{}.png'.format(datetime.strftime(datetime.now(), '%Y-%m-%d_%H:%M:%S:%f'))
    filepath = os.path.join(STATIC_DIR, filename)
    fig.savefig(filepath)
    return filename


if __name__ == '__main__':
    conn = sqlite3.connect(SQLITE_PATH)
    while True:
        capture = capture_traffic(packet_count=PACKET_COUNT)
        mean = statistic.calculate_online_mean(capture)
        dispersion = statistic.calculate_online_dispersion(capture, mean)
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

        data = format_packets(iter(capture))
        df = pd.DataFrame(data=data)
        protocol_size = get_protocol_size(df)
        protocol_count = get_protocol_count(df)
        mean_size_packet = get_mean_size_packet(protocol_size, protocol_count)
        filepaths = (
            save_plot(
                protocol_size,
                title='Общий размер пакетов сгруппирированных по протоколам',
                xlabel='Protocol',
                ylabel='Size (Mb)'
            ),
            save_plot(
                protocol_count,
                title='Количество пакетов сгруппирированных по протоколам',
                xlabel='Protocol',
                ylabel='Count'
            ),
            save_plot(
                mean_size_packet,
                title='Средние размеры пакета для каждого протокола',
                xlabel='Protocol',
                ylabel='Size (bytes)'
            ),
        )

        for filepath in filepaths:
            insert_file(conn, (statistic_id, filepath))
        print('25 end')
