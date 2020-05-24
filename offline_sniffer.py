import math

import pyshark

import statistic


if __name__ == '__main__':
    capture = pyshark.FileCapture('sniff_data/25_min.pcap')
    packets = capture._packets
    mean = statistic.calculate_mean(packets)  # 480567785.74765986
    dispersion = statistic.calculate_dispersion(packets, mean)
    standard_deviation = math.sqrt(dispersion)
    print(f'mean Mb = {statistic.get_mb_from_b(mean)}')
    print(f'dispersion Mb = {statistic.get_mb_from_b(dispersion)}')
    print(f'standard deviation Mb = {statistic.get_mb_from_b(standard_deviation)}')


# mean Mb = 458.30515455976473
# dispersion Mb = 382899858986.3845
# standard deviation Mb = 604.2861584306642
