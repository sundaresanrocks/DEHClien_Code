import time
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor


def example(n, sleep):
    time.sleep(sleep)
    return n, sleep


test_data = list(zip(range(1, 6), range(5, 0, -1)))

# with ThreadPoolExecutor() as pool:
#     futures = {pool.submit(example, n, s) for n, s in test_data}
#     for f in as_completed(futures):
#         print(f.result())

print('*' * 100)

with ThreadPoolExecutor() as pool:
    results = pool.map(example, *zip(*test_data))
    for res in results:
        print(res)