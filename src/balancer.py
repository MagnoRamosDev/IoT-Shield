import os
import glob
import numpy as np
import random
import csv
from collections import defaultdict

def run_balancing(tmp_dir, output_dir):
    chunk_files = sorted(glob.glob(os.path.join(tmp_dir, "*.npy")))
    if not chunk_files:
        print("[!] No extracted flows found. Exiting balancer.")
        return

    print(f"[*] Found {len(chunk_files)} binary chunks. Scanning frequencies (Pass 1)...")

    # --- Pass 1: count per (class, protocol) ---
    raw_counts = defaultdict(int)
    for fpath in chunk_files:
        try:
            chunk = np.load(fpath)
        except Exception:
            continue
        for row_idx in range(chunk.shape[0]):
            cls   = int(chunk[row_idx, 44])
            proto = int(chunk[row_idx, 2])
            raw_counts[(cls, proto)] += 1

    # Keep only groups with enough flows
    MIN_GROUP = 10000
    valid = {k: v for k, v in raw_counts.items() if v >= MIN_GROUP}

    if not valid:
        print(f"[!] No groups with >= {MIN_GROUP} flows found. Exiting.")
        return

    # --- Level 1: balance protocols WITHIN each class ---
    # group valid keys by class
    by_class = defaultdict(dict)   # cls -> {proto: count}
    for (cls, proto), count in valid.items():
        by_class[cls][proto] = count

    print("\n[*] Valid groups before balancing:")
    for cls in sorted(by_class):
        label = "Malicious" if cls == 1 else "Benign"
        for proto, cnt in sorted(by_class[cls].items()):
            print(f"  - {label} / Protocol {proto}: {cnt:,} flows")

    # Target per-protocol within each class = min across protocols in that class
    class_proto_target = {}   # cls -> flows_per_protocol
    class_n_protos     = {}   # cls -> number of protocols
    for cls, protos in by_class.items():
        class_proto_target[cls] = min(protos.values())
        class_n_protos[cls]     = len(protos)

    # Total per class after intra-class protocol balancing
    class_total = {cls: class_proto_target[cls] * class_n_protos[cls] for cls in by_class}

    # --- Level 2: balance BETWEEN classes (benign total == malicious total) ---
    target_per_class = min(class_total.values())

    # Recalculate per-protocol quota for each class so totals match
    # Distribute target_per_class equally across protocols within that class
    quota = {}   # (cls, proto) -> n_flows_to_sample
    print("\n[*] Final per-group quotas after two-level balancing:")
    for cls, protos in by_class.items():
        n_protos  = class_n_protos[cls]
        per_proto = target_per_class // n_protos   # floor — keep it clean
        label = "Malicious" if cls == 1 else "Benign"
        for proto in protos:
            quota[(cls, proto)] = per_proto
            print(f"  - {label} / Protocol {proto}: {per_proto:,} flows "
                  f"(original: {by_class[cls][proto]:,})")

    total_flows = sum(quota.values())
    print(f"\n[*] Target dataset size: {total_flows:,} flows total "
          f"({target_per_class:,} benign / {target_per_class:,} malicious)")

    # --- Pass 2: probabilistic reservoir sampling into train/test CSVs ---
    train_csv = os.path.join(output_dir, "train.csv")
    test_csv  = os.path.join(output_dir, "test.csv")

    csv_header = [
        "src_port", "dst_port", "protocol",
        "bidirectional_duration_ms", "bidirectional_packets",
        "src2dst_duration_ms", "src2dst_packets", "src2dst_bytes",
        "dst2src_duration_ms", "dst2src_packets", "dst2src_bytes",
        "bidirectional_min_ps", "bidirectional_max_ps", "bidirectional_mean_ps", "bidirectional_stddev_ps",
        "src2dst_min_ps", "src2dst_max_ps", "src2dst_mean_ps", "src2dst_stddev_ps",
        "dst2src_min_ps", "dst2src_max_ps", "dst2src_mean_ps", "dst2src_stddev_ps",
        "bidirectional_min_piat_ms", "bidirectional_max_piat_ms", "bidirectional_mean_piat_ms", "bidirectional_stddev_piat_ms",
        "src2dst_min_piat_ms", "src2dst_max_piat_ms", "src2dst_mean_piat_ms", "src2dst_stddev_piat_ms",
        "dst2src_min_piat_ms", "dst2src_max_piat_ms", "dst2src_mean_piat_ms", "dst2src_stddev_piat_ms",
        "src2dst_syn_packets", "dst2src_syn_packets", "bidirectional_syn_packets",
        "src2dst_rst_packets", "dst2src_rst_packets", "bidirectional_rst_packets",
        "src2dst_concurrent_flows", "dst2src_concurrent_flows", "bidirectional_concurrent_flows",
        "is_malicious"
    ]

    # Sampling state per (cls, proto):
    # split quota 50/50 between train and test
    sampling_state = {}
    for key, q in quota.items():
        half = q // 2
        total_raw = valid[key]
        sampling_state[key] = {
            'remaining_view':  total_raw,
            'remaining_train': half,
            'remaining_test':  q - half,
        }

    print("[*] Writing Final Balanced CSVs (Pass 2)...")

    with open(train_csv, "w", newline="") as f_train, open(test_csv, "w", newline="") as f_test:
        w_train = csv.writer(f_train)
        w_test  = csv.writer(f_test)
        w_train.writerow(csv_header)
        w_test.writerow(csv_header)

        for fpath in chunk_files:
            try:
                chunk = np.load(fpath)
            except Exception:
                continue

            for row_idx in range(chunk.shape[0]):
                cls   = int(chunk[row_idx, 44])
                proto = int(chunk[row_idx, 2])
                key   = (cls, proto)

                if key not in sampling_state:
                    continue

                state = sampling_state[key]
                rv  = state['remaining_view']
                rt  = state['remaining_train']
                rts = state['remaining_test']

                if rv <= 0:
                    continue

                total_pick = rt + rts
                if total_pick > 0:
                    r = random.random()
                    prob_train = rt / rv
                    prob_pick  = prob_train + rts / rv

                    if r < prob_train:
                        w_train.writerow(chunk[row_idx])
                        state['remaining_train'] -= 1
                    elif r < prob_pick:
                        w_test.writerow(chunk[row_idx])
                        state['remaining_test'] -= 1

                state['remaining_view'] -= 1

    train_rows = sum(q // 2       for q in quota.values())
    test_rows  = sum(q - q // 2   for q in quota.values())
    print(f"[*] Balancing complete! Datasets saved to: {train_csv} and {test_csv}")
    print(f"  - Train: ~{train_rows:,} rows")
    print(f"  - Test:  ~{test_rows:,} rows")
    print(f"  - Each class contributes exactly {target_per_class // class_n_protos.get(0,1):,} "
          f"flows per protocol per class")
