# Version 1.2.5 (20250311)
import os
import re
import csv
import glob
import datetime
import matplotlib.pyplot as plt
from tqdm import tqdm

# Excel 2007 以後的行數上限約 1,048,576，此處取 1,048,575 為安全數值
MAX_EXCEL_ROWS = 1048575

def extract_log_type(message):
    """
    從 log 訊息中擷取 log type：
    取從 "%" 開頭直到第一個空白字元為止的字串。
    若找不到則回傳 "Unknown"。
    """
    match = re.search(r"(%\S+)", message)
    if match:
        return match.group(1)
    return "Unknown"

def load_device_list():
    """
    讀取 deviceList.csv 檔案，預期每行格式為 "Type,Hostname,IP"，
    建立並回傳兩個映射字典：
      mapping_tfn: { IP: Hostname } (TFN 類)
      mapping_twm: { IP: Hostname } (TWM 類)
    若檔案不存在，回傳兩個空字典。
    """
    mapping_tfn = {}
    mapping_twm = {}
    device_file = "deviceList_v*.csv"
    if os.path.exists(device_file):
        with open(device_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) < 3:
                    continue
                dev_type = row[0].strip().upper()
                hostname = row[1].strip()
                ip = row[2].strip()
                if dev_type == "TFN":
                    mapping_tfn[ip] = hostname
                elif dev_type == "TWM":
                    mapping_twm[ip] = hostname
    return mapping_tfn, mapping_twm

def output_severity_count(out_folder, month_suffix, severity_counts):
    severity_count_list = []
    for syslog_type, data in severity_counts.items():
        severity_count_list.append({
            "Syslog Type": syslog_type,
            "Severity": data['severity'],
            "Count": data['count']
        })
    severity_count_list_sorted = sorted(severity_count_list, key=lambda x: x["Count"], reverse=True)
    filename = os.path.join(out_folder, f"severityCount_{month_suffix}.csv")
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["Syslog Type", "Severity", "Count"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in severity_count_list_sorted:
            writer.writerow(row)

def output_log_analysis(out_folder, month_suffix, log_rows):
    # 新增 "Log Type" 欄位
    new_rows = []
    for row in log_rows:
        new_row = row.copy()
        new_row["Log Type"] = extract_log_type(new_row["Syslog Message"])
        new_rows.append(new_row)
    if len(new_rows) > MAX_EXCEL_ROWS:
        chunks = [new_rows[i:i+MAX_EXCEL_ROWS] for i in range(0, len(new_rows), MAX_EXCEL_ROWS)]
        for i, chunk in enumerate(chunks, start=1):
            filename = os.path.join(out_folder, f"logAnalysis_{month_suffix}_part{i}.csv")
            with open(filename, "w", newline="", encoding="utf-8") as csvfile:
                fieldnames = ["Severity", "Device IP", "Hostname", "Log Type", "Syslog Message"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for row in chunk:
                    writer.writerow(row)
    else:
        filename = os.path.join(out_folder, f"logAnalysis_{month_suffix}.csv")
        with open(filename, "w", newline="", encoding="utf-8") as csvfile:
            fieldnames = ["Severity", "Device IP", "Hostname", "Log Type", "Syslog Message"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in new_rows:
                writer.writerow(row)

def output_log_count(out_folder, month_suffix, historical_counts):
    sorted_file_keys = sorted(historical_counts.keys(), key=lambda x: int(x))
    filename = os.path.join(out_folder, f"logCount_{month_suffix}.csv")
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["Month", "Sev0-3", "Sev4-6", "Total"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for month in sorted_file_keys:
            row = {
                "Month": month,
                "Sev0-3": historical_counts[month]['sev0_3'],
                "Sev4-6": historical_counts[month]['sev4_6'],
                "Total": historical_counts[month]['total']
            }
            writer.writerow(row)
        if len(sorted_file_keys) >= 2:
            last = sorted_file_keys[-1]
            second_last = sorted_file_keys[-2]
            diff_sev0_3 = historical_counts[last]['sev0_3'] - historical_counts[second_last]['sev0_3']
            diff_sev4_6 = historical_counts[last]['sev4_6'] - historical_counts[second_last]['sev4_6']
            diff_total = historical_counts[last]['total'] - historical_counts[second_last]['total']
            perc_sev0_3 = (diff_sev0_3 / historical_counts[second_last]['sev0_3'] * 100) if historical_counts[second_last]['sev0_3'] else 0
            perc_sev4_6 = (diff_sev4_6 / historical_counts[second_last]['sev4_6'] * 100) if historical_counts[second_last]['sev4_6'] else 0
            perc_total = (diff_total / historical_counts[second_last]['total'] * 100) if historical_counts[second_last]['total'] else 0
            diff_row = {
                "Month": "Diff Last Two",
                "Sev0-3": diff_sev0_3,
                "Sev4-6": diff_sev4_6,
                "Total": diff_total
            }
            perc_row = {
                "Month": "Perc Diff",
                "Sev0-3": f"{perc_sev0_3:.2f}%",
                "Sev4-6": f"{perc_sev4_6:.2f}%",
                "Total": f"{perc_total:.2f}%"
            }
            writer.writerow(diff_row)
            writer.writerow(perc_row)

def output_log_analysis_simple(out_folder, month_suffix, log_rows):
    simple_dict = {}
    for row in log_rows:
        message = row["Syslog Message"]
        tokens = message.split()
        day = (tokens[0] + " " + tokens[1]) if len(tokens) >= 2 else "Unknown"
        type_matches = re.findall(r"(%[^:]+):", message)
        syslog_type = type_matches[-1] if type_matches else "Unknown"
        key = (row["Device IP"], day, syslog_type)
        if key not in simple_dict:
            simple_dict[key] = (row, 1)
        else:
            existing_row, count = simple_dict[key]
            simple_dict[key] = (existing_row, count + 1)
    simple_results = []
    for key, (row, count) in simple_dict.items():
        new_row = {
            "Duplicates": count,
            "Severity": row["Severity"],
            "Device IP": row["Device IP"],
            "Hostname": row["Hostname"],
            "Log Type": extract_log_type(row["Syslog Message"]),
            "Syslog Message": row["Syslog Message"]
        }
        simple_results.append(new_row)
    filename = os.path.join(out_folder, f"logAnalysis_simple_{month_suffix}.csv")
    with open(filename, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["Duplicates", "Severity", "Device IP", "Hostname", "Log Type", "Syslog Message"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in simple_results:
            writer.writerow(row)

def output_trend(out_folder, historical_counts):
    sorted_file_keys = sorted(historical_counts.keys(), key=lambda x: int(x))
    formatted_months = [key[:4] + "-" + key[4:] for key in sorted_file_keys]
    sev0_3_counts = [historical_counts[m]['sev0_3'] for m in sorted_file_keys]
    sev4_6_counts = [historical_counts[m]['sev4_6'] for m in sorted_file_keys]
    
    # 產生 Severity 0-3 圖表
    plt.figure(figsize=(20, 5))
    plt.plot(formatted_months, sev0_3_counts, marker='o', label="Sev0-3", color='orange')
    plt.xlabel("Month")
    plt.ylabel("Log Count")
    plt.title("Historical Log Count (Sev0-3)")
    plt.legend()
    plt.grid(True)
    trend_file_03 = os.path.join(out_folder, "log_trend_0-3.png")
    plt.savefig(trend_file_03)
    plt.close()
    
    # 產生 Severity 4-6 圖表
    plt.figure(figsize=(20, 5))
    plt.plot(formatted_months, sev4_6_counts, marker='o', label="Sev4-6", color='blue')
    plt.xlabel("Month")
    plt.ylabel("Log Count")
    plt.title("Historical Log Count (Sev4-6)")
    plt.legend()
    plt.grid(True)
    trend_file_46 = os.path.join(out_folder, "log_trend_4-6.png")
    plt.savefig(trend_file_46)
    plt.close()

def output_pie_charts(out_folder, log_rows, month_suffix):
    """
    根據 logAnalysis 的資料來產生圓餅圖。
    以 syslog type 分組，每個圓餅圖統計該 type 各設備 (以 Hostname 為主) 的比例，
    若超過 5 筆則僅顯示前 5 名，其餘統整為 "Other"。
    圓餅圖存檔時會移除 log type 中的不合法字元，並正確加上 .png 副檔名，
    圖中顯示百分比及實際次數。
    """
    def make_autopct(values):
        def my_autopct(pct):
            total = sum(values)
            count = int(round(pct*total/100.0))
            return '{p:.1f}% ({v:d})'.format(p=pct, v=count)
        return my_autopct

    pie_data = {}
    for row in log_rows:
        log_type = extract_log_type(row["Syslog Message"])
        device = row.get("Hostname", row.get("Device IP", "Unknown"))
        if log_type not in pie_data:
            pie_data[log_type] = {}
        if device not in pie_data[log_type]:
            pie_data[log_type][device] = 0
        pie_data[log_type][device] += 1

    for log_type, device_counts in pie_data.items():
        # 清理 log_type：移除 "%" 與 Windows 不允許的字元
        log_type_clean = re.sub(r'[\\/*?:"<>|%]', '', log_type)
        sorted_devices = sorted(device_counts.items(), key=lambda x: x[1], reverse=True)
        if len(sorted_devices) > 5:
            top_devices = sorted_devices[:5]
            others_total = sum(count for device, count in sorted_devices[5:])
            top_devices.append(("Other", others_total))
        else:
            top_devices = sorted_devices
        labels = [device for device, count in top_devices]
        sizes = [count for device, count in top_devices]
        plt.figure(figsize=(8, 8))
        plt.pie(sizes, labels=labels, autopct=make_autopct(sizes), startangle=140)
        plt.title(f"{log_type_clean} ({month_suffix})")
        pie_filename = os.path.join(out_folder, f"{log_type_clean}_pie_{month_suffix}.png")
        plt.savefig(pie_filename)
        plt.close()

def main():
    # 掃描目錄下所有符合 YYYYMM.txt 格式的檔案
    files = [f for f in glob.glob("*.txt") if re.match(r"\d{6}\.txt$", f)]
    if not files:
        print("No valid txt files found in the format YYYYMM.txt.")
        return
    print("Found the following files:")
    for idx, file in enumerate(files, start=1):
        print(f"{idx}. {file}")
    selection = input("Enter the file numbers to analyze (comma separated). Leave blank to analyze all: ").strip()
    if selection == "":
        confirm = input("No numbers entered. Do you want to analyze all files? (y/n): ").strip().lower()
        if confirm not in ["y", "yes", ""]:
            print("Analysis canceled.")
            return
        indices = list(range(1, len(files) + 1))
    else:
        try:
            indices = [int(x.strip()) for x in selection.split(",") if x.strip().isdigit()]
        except Exception:
            print("Invalid input format.")
            return
    selected_files = [files[i - 1] for i in indices if 1 <= i <= len(files)]
    if not selected_files:
        print("No valid files selected.")
        return
    sorted_files = sorted(selected_files, key=lambda f: int(os.path.splitext(f)[0]))
    latest_file = sorted_files[-1]
    latest_month = os.path.splitext(latest_file)[0]
    month_suffix = latest_month[-2:]
    print(f"Latest file for CSV analysis: {latest_file}")
    # 載入 deviceList.csv (格式: Type,Hostname,IP)
    mapping_tfn, mapping_twm = load_device_list()
    # ① 歷史資料統計（用於折線圖）：分別統計 TFN、TWM 與 UNKNOWN
    historical_counts_tfn = {}
    historical_counts_twm = {}
    historical_counts_unknown = {}
    for file in selected_files:
        file_key = os.path.splitext(file)[0]
        historical_counts_tfn[file_key] = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
        historical_counts_twm[file_key] = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
        historical_counts_unknown[file_key] = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
        with open(file, "r", encoding="utf-8") as f:
            lines = f.readlines()
        for line in tqdm(lines, desc=f"Historical Processing {file}"):
            line = line.strip()
            if not line:
                continue
            sev_match = re.search(r"%\S+-(\d)-\S+:", line)
            if not sev_match:
                continue
            try:
                severity = int(sev_match.group(1))
            except Exception:
                continue
            tokens = line.split()
            if len(tokens) < 4:
                continue
            device_ip = tokens[3]
            if device_ip in mapping_tfn:
                category = "TFN"
            elif device_ip in mapping_twm:
                category = "TWM"
            else:
                category = "UNKNOWN"
            if category == "TFN":
                if 0 <= severity <= 3:
                    historical_counts_tfn[file_key]['sev0_3'] += 1
                elif 4 <= severity <= 6:
                    historical_counts_tfn[file_key]['sev4_6'] += 1
                historical_counts_tfn[file_key]['total'] += 1
            elif category == "TWM":
                if 0 <= severity <= 3:
                    historical_counts_twm[file_key]['sev0_3'] += 1
                elif 4 <= severity <= 6:
                    historical_counts_twm[file_key]['sev4_6'] += 1
                historical_counts_twm[file_key]['total'] += 1
            else:
                if 0 <= severity <= 3:
                    historical_counts_unknown[file_key]['sev0_3'] += 1
                elif 4 <= severity <= 6:
                    historical_counts_unknown[file_key]['sev4_6'] += 1
                historical_counts_unknown[file_key]['total'] += 1
    # ② 最新月份資料分析（僅處理最新檔案），分別對 TFN、TWM 與 UNKNOWN
    severity_latest_tfn = {}
    log_analysis_latest_tfn = []
    latest_count_tfn = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
    
    severity_latest_twm = {}
    log_analysis_latest_twm = []
    latest_count_twm = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
    
    severity_latest_unknown = {}
    log_analysis_latest_unknown = []
    latest_count_unknown = {'sev0_3': 0, 'sev4_6': 0, 'total': 0}
    
    with open(latest_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    for line in tqdm(lines, desc=f"Processing Latest File {latest_file}"):
        line = line.strip()
        if not line:
            continue
        sev_match = re.search(r"%\S+-(\d)-\S+:", line)
        if not sev_match:
            continue
        try:
            severity = int(sev_match.group(1))
        except Exception:
            continue
        tokens = line.split()
        if len(tokens) < 4:
            continue
        device_ip = tokens[3]
        if device_ip in mapping_tfn:
            category = "TFN"
        elif device_ip in mapping_twm:
            category = "TWM"
        else:
            category = "UNKNOWN"
        if category == "TFN":
            if 0 <= severity <= 6:
                type_matches = re.findall(r"(%[^:]+):", line)
                syslog_type = type_matches[-1] if type_matches else "Unknown"
                if syslog_type not in severity_latest_tfn:
                    severity_latest_tfn[syslog_type] = {'severity': severity, 'count': 0}
                severity_latest_tfn[syslog_type]['count'] += 1
            if 0 <= severity <= 3:
                latest_count_tfn['sev0_3'] += 1
                log_analysis_latest_tfn.append({
                    "Severity": severity,
                    "Device IP": device_ip,
                    "Syslog Message": line
                })
            elif 4 <= severity <= 6:
                latest_count_tfn['sev4_6'] += 1
            latest_count_tfn['total'] += 1
        elif category == "TWM":
            if 0 <= severity <= 6:
                type_matches = re.findall(r"(%[^:]+):", line)
                syslog_type = type_matches[-1] if type_matches else "Unknown"
                if syslog_type not in severity_latest_twm:
                    severity_latest_twm[syslog_type] = {'severity': severity, 'count': 0}
                severity_latest_twm[syslog_type]['count'] += 1
            if 0 <= severity <= 3:
                latest_count_twm['sev0_3'] += 1
                log_analysis_latest_twm.append({
                    "Severity": severity,
                    "Device IP": device_ip,
                    "Syslog Message": line
                })
            elif 4 <= severity <= 6:
                latest_count_twm['sev4_6'] += 1
            latest_count_twm['total'] += 1
        else:
            if 0 <= severity <= 6:
                type_matches = re.findall(r"(%[^:]+):", line)
                syslog_type = type_matches[-1] if type_matches else "Unknown"
                if syslog_type not in severity_latest_unknown:
                    severity_latest_unknown[syslog_type] = {'severity': severity, 'count': 0}
                severity_latest_unknown[syslog_type]['count'] += 1
            if 0 <= severity <= 3:
                latest_count_unknown['sev0_3'] += 1
                log_analysis_latest_unknown.append({
                    "Severity": severity,
                    "Device IP": device_ip,
                    "Syslog Message": line
                })
            elif 4 <= severity <= 6:
                latest_count_unknown['sev4_6'] += 1
            latest_count_unknown['total'] += 1
    for row in log_analysis_latest_tfn:
        ip = row["Device IP"]
        row["Hostname"] = mapping_tfn.get(ip, "N/A")
    for row in log_analysis_latest_twm:
        ip = row["Device IP"]
        row["Hostname"] = mapping_twm.get(ip, "N/A")
    for row in log_analysis_latest_unknown:
        row["Hostname"] = "N/A"
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    out_folder_tfn = f"DCN_Syslog_TFN_{timestamp}"
    out_folder_twm = f"DCN_Syslog_TWM_{timestamp}"
    out_folder_unknown = f"DCN_Syslog_UNKNOWN_{timestamp}"
    os.makedirs(out_folder_tfn, exist_ok=True)
    os.makedirs(out_folder_twm, exist_ok=True)
    os.makedirs(out_folder_unknown, exist_ok=True)
    output_severity_count(out_folder_tfn, month_suffix, severity_latest_tfn)
    output_severity_count(out_folder_twm, month_suffix, severity_latest_twm)
    output_severity_count(out_folder_unknown, month_suffix, severity_latest_unknown)
    output_log_analysis(out_folder_tfn, month_suffix, log_analysis_latest_tfn)
    output_log_analysis(out_folder_twm, month_suffix, log_analysis_latest_twm)
    output_log_analysis(out_folder_unknown, month_suffix, log_analysis_latest_unknown)
    output_log_count(out_folder_tfn, month_suffix, historical_counts_tfn)
    output_log_count(out_folder_twm, month_suffix, historical_counts_twm)
    output_log_count(out_folder_unknown, month_suffix, historical_counts_unknown)
    output_log_analysis_simple(out_folder_tfn, month_suffix, log_analysis_latest_tfn)
    output_log_analysis_simple(out_folder_twm, month_suffix, log_analysis_latest_twm)
    output_log_analysis_simple(out_folder_unknown, month_suffix, log_analysis_latest_unknown)
    output_trend(out_folder_tfn, historical_counts_tfn)
    output_trend(out_folder_twm, historical_counts_twm)
    output_trend(out_folder_unknown, historical_counts_unknown)
    def output_pie_charts(out_folder, log_rows, month_suffix):
        """
        根據 logAnalysis 的資料來產生圓餅圖。
        以 syslog type 分組，每個圓餅圖統計該 type 各設備 (以 Hostname 為主) 的比例，
        若超過 5 筆則僅顯示前 5 名，其餘統整為 "Other"。
        圓餅圖存檔時會移除 log type 中的不合法字元，並正確加上 .png 副檔名，
        圖中顯示百分比及實際次數。
        """
        def make_autopct(values):
            def my_autopct(pct):
                total = sum(values)
                count = int(round(pct*total/100.0))
                return '{p:.1f}% ({v:d})'.format(p=pct, v=count)
            return my_autopct

        pie_data = {}
        for row in log_rows:
            log_type = extract_log_type(row["Syslog Message"])
            device = row.get("Hostname", row.get("Device IP", "Unknown"))
            if log_type not in pie_data:
                pie_data[log_type] = {}
            if device not in pie_data[log_type]:
                pie_data[log_type][device] = 0
            pie_data[log_type][device] += 1

        for log_type, device_counts in pie_data.items():
            log_type_clean = re.sub(r'[\\/*?:"<>|%]', '', log_type)
            sorted_devices = sorted(device_counts.items(), key=lambda x: x[1], reverse=True)
            if len(sorted_devices) > 5:
                top_devices = sorted_devices[:5]
                others_total = sum(count for device, count in sorted_devices[5:])
                top_devices.append(("Other", others_total))
            else:
                top_devices = sorted_devices
            labels = [device for device, count in top_devices]
            sizes = [count for device, count in top_devices]
            plt.figure(figsize=(8, 8))
            plt.pie(sizes, labels=labels, autopct=make_autopct(sizes), startangle=140)
            plt.title(f"{log_type_clean} ({month_suffix})")
            pie_filename = os.path.join(out_folder, f"{log_type_clean}_pie_{month_suffix}.png")
            plt.savefig(pie_filename)
            plt.close()
    output_pie_charts(out_folder_tfn, log_analysis_latest_tfn, month_suffix)
    output_pie_charts(out_folder_twm, log_analysis_latest_twm, month_suffix)
    output_pie_charts(out_folder_unknown, log_analysis_latest_unknown, month_suffix)
    print("\nAnalysis complete!")
    print("TFN output files are saved in folder:", out_folder_tfn)
    print("TWM output files are saved in folder:", out_folder_twm)
    print("UNKNOWN output files are saved in folder:", out_folder_unknown)

if __name__ == "__main__":
    main()
