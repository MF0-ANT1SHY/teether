import cmd
import os
import subprocess
from multiprocessing import Pool
import psutil
import csv
import time
import json


def append_to_csv(contract, duration):
    filename = "duration.csv"
    file_exists = os.path.isfile(filename)

    with open(filename, "a", newline="") as csvfile:
        fieldnames = ["contract", "duration"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()  # 如果文件不存在，写入标题行

        writer.writerow(
            {
                "contract": contract,
                "duration": duration,
            }
        )


def run_process(file, timeoutsize=2 * 60, vul="Reentrancy"):
    starttime = time.time()
    name = file.rsplit("/", 1)[-1]
    cmd = ["python3", "bin/gen_exploit.py", file, "0x1234", "0x1000", "+1000"]
    try:
        subprocess.run(cmd, timeout=timeoutsize)
    except subprocess.TimeoutExpired:
        endtime = time.time()
        duration = endtime - starttime
    finally:
        endtime = time.time()
        duration = endtime - starttime
        append_to_csv(name, duration)


def main(timeout=2 * 60, from_dir="./", vul="Reentrancy"):
    # 获取系统的内存和CPU信息
    mem = psutil.virtual_memory()
    available_memory_gb = mem.available / (1024**3)  # 可用内存转换为GB
    cpu_count = psutil.cpu_count(logical=False)  # 获取物理核心数

    memory_per_process_gb = 8
    max_processes_by_memory = int(available_memory_gb / memory_per_process_gb)
    max_processes_by_cpu = cpu_count

    num_processes = min(max_processes_by_memory, max_processes_by_cpu)
    print(f"Starting {num_processes} processes...")

    directories = [
        os.path.expanduser(from_dir),
    ]

    pool = Pool(num_processes)
    print(pool._cache)

    filelist = []

    for directory_path in directories:
        for filename in os.listdir(directory_path):
            if filename.endswith(".hex") or filename.endswith(".code"):
                full_path = os.path.join(directory_path, filename)
                filelist.append(full_path)

    for path in filelist:
        pool.apply_async(
            run_process,
            (path, timeout, vul),
        )
    pool.close()
    pool.join()


if __name__ == "__main__":
    with open("config.json", "r") as file:
        config = json.load(file)
        first_config = config[0]

        timeout = first_config["timeout"]
        from_dir = first_config["from"]
        vul = "None"
    main(timeout, from_dir, vul)
