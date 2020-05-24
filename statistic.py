import math


def get_difference_time(packet1, packet2):
    return float(packet1.sniff_timestamp) - float(packet2.sniff_timestamp)


def get_bytes_per_second(current, previous):
    duration = get_difference_time(current, previous)
    return float(current.length) / duration


def get_mb_from_b(bytes):
    return bytes / 1024 / 1024


def calculate_mean(packets):
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


def calculate_dispersion(packets, mean):
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
