import argparse
import sys
import os
import shutil

from src.extractor import run_extraction
from src.balancer import run_balancing
from src.trainer import run_training
from src.dashboard import start_dashboard, stop_dashboard

def main():
    parser = argparse.ArgumentParser(description="AI Pipeline for PCAP Random Forest Feature Extraction")
    parser.add_argument("--workers", type=int, default=4, help="Number of multiprocess workers to use")
    parser.add_argument("--max-ram", type=int, default=1024, help="Max RAM to allocate for data buffers in MB")
    parser.add_argument("--split-size", type=int, default=0, help="If > 0, split input PCAPs into chunks of this many MB before parsing")
    parser.add_argument("--dataset-list", type=str, default="data/datasets_list.txt", help="Path to datasets_list.txt")
    parser.add_argument("--tmp-dir", type=str, default="data/tmp", help="Path to store temporary numpy chunks")
    parser.add_argument("--output-dir", type=str, default="results", help="Path to store final CSVs")
    parser.add_argument("--exclude-list", type=str, default="config/excluded_features.txt", help="File listing features to drop before training")
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Classification threshold (0.0-1.0). Higher = less false positives on benign, but more malicious slips through. Default: 0.5")
    parser.add_argument("--phase", type=str, choices=["all", "extract", "balance", "train"], default="all", help="Which portion of the pipeline to run")

    args = parser.parse_args()

    print(f"[+] Starting pipeline with {args.workers} workers and {args.max_ram}MB max RAM.")

    # Clean up tmp directory if it exists and recreate it
    if args.phase in ["all", "extract"]:
        if os.path.exists(args.tmp_dir):
            shutil.rmtree(args.tmp_dir)
        os.makedirs(args.tmp_dir, exist_ok=True)
    os.makedirs(args.output_dir, exist_ok=True)

    # Start dashboard in the background only if not purely training
    if args.phase != "train":
        start_dashboard()

    try:
        # Step 1: Extractor
        if args.phase in ["all", "extract"]:
            print("\n[+] Phase 1: Feature Extraction")
            # Split Data if required
            working_dataset_list = args.dataset_list
            if args.split_size > 0:
                print(f"\n[+] Splitting large PCAP files into chunks of {args.split_size} MB using {args.workers} workers...")
                from src.extractor import split_pcaps_if_needed
                working_dataset_list = split_pcaps_if_needed(args.dataset_list, args.split_size, args.tmp_dir, args.workers)

            run_extraction(
                dataset_list_path=working_dataset_list,
                workers=args.workers,
                max_ram_mb=args.max_ram,
                tmp_dir=args.tmp_dir
            )

        # Step 2: Balancer
        if args.phase in ["all", "balance"]:
            print("\n[+] Phase 2: Flow Balancing & Splitting")
            run_balancing(
                tmp_dir=args.tmp_dir,
                output_dir=args.output_dir
            )

        # Step 3: Train Random Forest Model
        if args.phase in ["all", "train"]:
            print("\n[+] Phase 3: Train Random Forest Model")
            run_training(
                train_csv=os.path.join(args.output_dir, "train.csv"),
                test_csv=os.path.join(args.output_dir, "test.csv"),
                exclude_file=args.exclude_list,
                threshold=args.threshold,
            )

        print("\n[+] Pipeline Complete! Deleting temporary binaries...")
    except KeyboardInterrupt:
        print("\n[!] Pipeline interrupted by user.")
    except Exception as e:
        print(f"\n[!] Pipeline failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if args.phase != "train":
            stop_dashboard()
        if args.phase in ["all", "balance"] and os.path.exists(args.tmp_dir):
            shutil.rmtree(args.tmp_dir)
        print("[+] Goodbye!")

if __name__ == "__main__":
    main()
