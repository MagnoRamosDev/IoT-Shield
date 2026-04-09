import os
import glob
import numpy as np
import random
import csv

def run_balancing(tmp_dir, output_dir):
    chunk_files = sorted(glob.glob(os.path.join(tmp_dir, "*.npy")))
    if not chunk_files:
        print("[!] No extracted flows found. Exiting balancer.")
        return

    print(f"[*] Found {len(chunk_files)} binary chunks. Scanning frequencies (Pass 1)...")

    # Step 1: Count frequencies of each class
    # We will map class_key -> total_count
    # class_key is (is_malicious, protocol)
    class_counts = {}

    for chunk_idx, fpath in enumerate(chunk_files):
        try:
            chunk = np.load(fpath)
        except Exception:
            continue
            
        for row_idx in range(chunk.shape[0]):
            protocol = int(chunk[row_idx, 2])
            is_malicious = int(chunk[row_idx, 35])
            key = (is_malicious, protocol)
            
            class_counts[key] = class_counts.get(key, 0) + 1

    # Calculate valid groups and target MIN_FLOWS
    valid_groups = {}
    for key, count in class_counts.items():
        if count >= 1000:
            valid_groups[key] = count
            print(f"  - Group (Malicious={key[0]}, Protocol={key[1]}): {count} flows (VALID)")
        else:
            print(f"  - Group (Malicious={key[0]}, Protocol={key[1]}): {count} flows (DISCARDED)")

    if not valid_groups:
        print("[!] No groups with >= 1000 flows found. Exiting.")
        return

    min_flows = min(valid_groups.values())
    print(f"[*] Balancing all valid groups exactly to MIN_FLOWS = {min_flows}")

    # Prepare sampling state for Phase 2
    sampling_state = {}
    for key, count in valid_groups.items():
        half = min_flows // 2
        sampling_state[key] = {
            'remaining_view': count,
            'remaining_train': half,
            'remaining_test': min_flows - half
        }
    
    # Step 2: Write to CSV using an O(1) memory probabilisitic sampling algorithms
    train_csv = os.path.join(output_dir, "train.csv")
    test_csv = os.path.join(output_dir, "test.csv")
    
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
        "is_malicious"
    ]

    print("[*] Writing Final Balanced CSVs (Pass 2)...")
    
    with open(train_csv, "w", newline="") as f_train, open(test_csv, "w", newline="") as f_test:
        w_train = csv.writer(f_train)
        w_test = csv.writer(f_test)
        
        w_train.writerow(csv_header)
        w_test.writerow(csv_header)

        for chunk_idx, fpath in enumerate(chunk_files):
            try:
                chunk = np.load(fpath)
            except Exception:
                continue

            for row_idx in range(chunk.shape[0]):
                protocol = int(chunk[row_idx, 2])
                is_malicious = int(chunk[row_idx, 35])
                key = (is_malicious, protocol)
                
                if key in sampling_state:
                    state = sampling_state[key]
                    rv = state['remaining_view']
                    rt = state['remaining_train']
                    rts = state['remaining_test']
                    
                    if rv <= 0:
                        continue # Should theoretically never happen
                        
                    total_pick = rt + rts
                    
                    if total_pick > 0:
                        # Decide probabilistically
                        r = random.random()
                        prob_train = rt / rv
                        prob_test = rts / rv
                        prob_pick = prob_train + prob_test
                        
                        if r < prob_train:
                            w_train.writerow(chunk[row_idx])
                            state['remaining_train'] -= 1
                        elif r < prob_pick:
                            w_test.writerow(chunk[row_idx])
                            state['remaining_test'] -= 1
                            
                    state['remaining_view'] -= 1
                    
    print(f"[*] Balancing complete! Datasets saved to: {train_csv} and {test_csv}")
    
    # Count rows written for debugging
    train_rows = sum((min_flows // 2) for _ in valid_groups)
    test_rows = sum((min_flows - (min_flows // 2)) for _ in valid_groups)
    print(f"  - Train: {train_rows} rows")
    print(f"  - Test : {test_rows} rows")
