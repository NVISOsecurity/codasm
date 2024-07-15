"""Basic implementation of Shannon entropy calculation
Based on https://cocomelonc.github.io/malware/2022/11/05/malware-analysis-6.html
"""

import math


def shannon_entropy(data: bytes) -> float:
    """Calculates the Shannon entropy of the given data blob"""

    # Counts of possible values
    possible = [0 for i in range(256)]

    for b in data:
        possible[b] += 1

    data_len = len(data)
    entropy = 0.0

    # compute
    for i in range(256):
        if possible[i] == 0:
            continue

        p = float(possible[i] / data_len)
        entropy -= p * math.log(p, 2)
    return entropy
