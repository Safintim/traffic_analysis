import math
import pyshark
import statistic
import pandas as pd

STATIC_DIR = 'static'


if __name__ == '__main__':
    capture = pyshark.FileCapture(
        'sniff_data/25_min.pcapng',
        keep_packets=False,
    )
    mean = statistic.calculate_mean(iter(capture))
    dispersion = statistic.calculate_dispersion(iter(capture), mean)
    standard_deviation = math.sqrt(dispersion)

    print(f'mean b = {mean}')
    print(f'dispersion b = {dispersion}')
    print(f'standard deviation b = {standard_deviation}')

    print(f'mean Mb = {statistic.get_mb_from_b(mean)}')
    print(f'dispersion Mb = {statistic.get_mb_from_b_for_dispersion(dispersion)}')
    print(f'standard deviation Mb = {statistic.get_mb_from_b(standard_deviation)}')

    df = pd.read_csv('sniff_data/25_min.csv')
    protocol_size = statistic.get_protocol_size(df)
    protocol_count = statistic.get_protocol_count(df)
    mean_size_packet = statistic.get_mean_size_packet(protocol_size, protocol_count)
    statistic.save_plot(
                protocol_size,
                title='Общий размер пакетов сгруппированных по протоколам',
                xlabel='Protocol',
                ylabel='Size (Mb)',
                static_dir=STATIC_DIR,
            )
    statistic.save_plot(
        protocol_count,
        title='Количество пакетов сгруппированных по протоколам',
        xlabel='Protocol',
        ylabel='Count',
        static_dir=STATIC_DIR,
    )
    statistic.save_plot(
        mean_size_packet,
        title='Средние размеры пакета для каждого протокола',
        xlabel='Protocol',
        ylabel='Size (bytes)',
        static_dir=STATIC_DIR,
    )