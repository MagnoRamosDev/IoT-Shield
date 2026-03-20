# src/utils/data_loader.py
import os
import glob
import pandas as pd
import numpy as np

def load_datasets_smart(folder_path, sample_rate=0.05):
    """
    Lê arquivos CSV em chunks. 
    Mantém 100% do tráfego benigno (0) e faz undersampling no botnet (1).
    """
    all_files = glob.glob(os.path.join(folder_path, "*.csv"))
    if not all_files:
        print(f"[ERROR] Nenhum arquivo CSV encontrado em {folder_path}")
        return None
    
    df_list = []
    
    for file in all_files:
        print(f"  -> Carregando {os.path.basename(file)} em chunks...")
        chunk_iterator = pd.read_csv(file, chunksize=5000000)
        
        for chunk in chunk_iterator:
            normal_traffic = chunk[chunk['label'] == 0]
            botnet_traffic = chunk[chunk['label'] == 1]
            
            if len(botnet_traffic) > 0:
                botnet_traffic = botnet_traffic.sample(frac=sample_rate, random_state=42)
            
            df_list.append(normal_traffic)
            df_list.append(botnet_traffic)
            
    combined_df = pd.concat(df_list, ignore_index=True)
    combined_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    combined_df.fillna(0, inplace=True)
    
    return combined_df