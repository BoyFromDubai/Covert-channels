import json
import pandas
import matplotlib.pyplot as plt
from matplotlib.pyplot import savefig
import math
import sys
import statistics
import os

STEP_FOR_BINS = 0.25
STEP_TO_ROUND = 10 ** str(STEP_FOR_BINS)[::-1].find('.')
START_OF_SEC_MSG = 99

def save_hist(data: list, bins: list, file_name='Hist', hist_color='green', title='Hist', x_lable='X', y_lable='Y'):
    plt.clf()    
    plt.hist(data, bins=bins, edgecolor='black', color=hist_color)
    
    plt.xlabel(x_lable)
    plt.ylabel(y_lable)
    
    plt.title(title, fontweight ="bold")

    savefig(file_name)

def get_bins(data: list):
    min_val = math.floor(min(data))
    max_val = math.ceil(max(data)) + STEP_FOR_BINS

    return list(map(lambda x: x / STEP_TO_ROUND, [i for i in range(min_val * STEP_TO_ROUND, int(max_val * STEP_TO_ROUND), int(STEP_FOR_BINS * STEP_TO_ROUND))]))

def get_intervals(packets: list):
    intervals = []
    prev = ''

    for packet in packets:
        pkt_data_time = packet['_source']['layers']['frame']['frame.time']
        format_time = '%b %d, %Y %H:%M:%S.%f'
        pkt_date = pandas.to_datetime(pkt_data_time[:-4], format=format_time)

        if not prev:
            prev = pkt_date
        else:
            interval = (pkt_date - prev).total_seconds()
            intervals.append(interval)
        
        prev = pkt_date

    return intervals


def get_pos_of_bin(time: float, bins: list):
    for border in bins:
        if time < border:
            return border

def sort_intervals_by_bins(intervals: list, bins: list):
    intervals_dict = {border: [] for border in bins}

    for i, interval in enumerate(intervals):
        upper_border = get_pos_of_bin(interval, bins)
        intervals_dict[upper_border].append(i)

    keys = list(intervals_dict.keys())
    keys.sort()
    sorted_dict = {i: intervals_dict[i] for i in keys}

    return sorted_dict
        
def get_peaks_keys(intervals_by_bins: dict):
    max_1_key = None
    max_1_val = -1
    max_2_key = None
    max_2_val = -1
    local_min_key = None
    local_min_val = sys.maxsize

    for key, val in intervals_by_bins.items():
        tmp = len(val)

        if max_1_val < tmp:
            max_1_key = key
            max_1_val = tmp
        elif local_min_val > tmp:
            local_min_key = key
            local_min_val = tmp
        elif max_2_val < tmp:
            max_2_key = key
            max_2_val = tmp
            break
    
    return max_1_key, local_min_key, max_2_key

def get_peaks_vals(intervals_by_bins: dict): 
    max_1, local_min, max_2 = get_peaks_keys(intervals_by_bins)
    
    return len(intervals_by_bins[max_1]), len(intervals_by_bins[local_min]), len(intervals_by_bins[max_2])

def get_covert_channel_possibility(maxs: tuple, local_min): return 1 - local_min / max(maxs)

def decode(intervals: list):
    covert_message = ''

    for interval in intervals:
        if interval < statistics.mean(intervals):
            covert_message += '1'
        else:
            covert_message += '0'

    string = []
    
    for i in range(0, len(covert_message), 8):
        string += chr(int(covert_message[i:i + 8], 2))

    return ''.join(string)

if __name__  == '__main__':
    filename = os.path.join('data','5.json')
    packets = []

    with open(filename, 'r') as f:
        packets = json.loads(f.read())     

    intervals = get_intervals(packets)
    interval_bins = get_bins(intervals)
    save_hist(intervals, interval_bins, os.path.join('imgs', '1st hist'), 'blue', 'Intervals', 'interval', 'N')
    intervals_by_bins = sort_intervals_by_bins(intervals, interval_bins)

    max_1, local_min, max_2 = get_peaks_vals(intervals_by_bins)
    print("Possibility of covert channel in all packets: ", get_covert_channel_possibility((max_1, max_2), local_min))
    
    cvrt_chnnl_intervals = intervals[START_OF_SEC_MSG:]
    cvrt_chnnl_interval_bins = get_bins(cvrt_chnnl_intervals)
    save_hist(cvrt_chnnl_intervals, cvrt_chnnl_interval_bins, os.path.join('imgs', '2st hist'), 'blue', f'Intervals starting with {START_OF_SEC_MSG} packet', 'interval', 'N')
    cvrt_chnnl_intervals_by_bins = sort_intervals_by_bins(cvrt_chnnl_intervals, cvrt_chnnl_interval_bins)

    max_1, local_min, max_2 = get_peaks_vals(cvrt_chnnl_intervals_by_bins)
    print(f"Possibility of covert channel starting with {START_OF_SEC_MSG} packet: ", get_covert_channel_possibility((max_1, max_2), local_min))

    print("Decodes msg:", decode(cvrt_chnnl_intervals))