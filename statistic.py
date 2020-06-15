import os
import math
from datetime import datetime

import matplotlib.pyplot as plt
import numpy as np


def get_difference_time(packet1, packet2):
    return float(packet1.sniff_timestamp) - float(packet2.sniff_timestamp)


def get_bytes_per_second(current, previous):
    duration = get_difference_time(current, previous)
    return float(current.length) / duration


def get_mb_from_b(bytes):
    return bytes / 1024 / 1024


def get_mb_from_b_for_dispersion(bytes):
    x = 1024 ** 2
    return bytes / x / x


def calculate_mean(packets):
    bps_collection = 0
    count = 0

    previous = next(packets)
    for current in packets:
        if get_difference_time(current, previous) != 0:
            bps_collection += get_bytes_per_second(current, previous)
            previous = current
            count += 1
    return bps_collection / count


def calculate_dispersion(packets, mean):
    bps_collection = 0
    count = 0

    previous = next(packets)
    for current in packets:
        if get_difference_time(current, previous) != 0:
            diff = get_bytes_per_second(current, previous) - mean
            bps_collection += math.pow(diff, 2)
            previous = current
            count += 1
    return bps_collection / count


def calculate_online_mean(packets):
    bps_collection = 0
    count = 0

    previous = packets[0]
    for i in range(1, len(packets)):
        current = packets[i]
        if get_difference_time(current, previous) != 0:
            bps_collection += get_bytes_per_second(current, previous)
            previous = current
            count += 1
    return bps_collection / count


def calculate_online_dispersion(packets, mean):
    bps_collection = 0
    count = 0

    previous = packets[0]
    for i in range(1, len(packets)):
        current = packets[i]
        if get_difference_time(current, previous) != 0:
            diff = get_bytes_per_second(current, previous) - mean
            bps_collection += math.pow(diff, 2)
            previous = current
            count += 1
    return bps_collection / count


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
    df_sum_length_mb = get_mb_from_b(df_sum_length)
    df_sum_length_mb.sort_values(ascending=False)
    return df_sum_length_mb


def get_mean_size_packet(df_size, df_count):
    """
    Средний размер пакета для протокола
    """
    return df_size / df_count


def save_plot(df, title, xlabel, ylabel, static_dir):
    plot = df.plot(
        kind='bar',
        color=plt.cm.Paired(np.arange(len(df))),
        title=title
    )
    plot.set_xlabel(xlabel)
    plot.set_ylabel(ylabel)
    fig = plot.get_figure()
    filename = '{}.png'.format(datetime.strftime(datetime.now(), '%Y-%m-%d_%H:%M:%S:%f'))
    filepath = os.path.join(static_dir, filename)
    fig.savefig(filepath)
    return filename
