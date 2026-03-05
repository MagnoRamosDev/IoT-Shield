# export_to_c.py
import joblib
import m2cgen as m2c

def export_model():
    model_path = 'results/iot_shield_model.pkl'
    
    print("[INFO] Loading pre-trained model...")
    model = joblib.load(model_path)

    print("[INFO] Converting model to C code...")
    print("[INFO] This process may take several minutes depending on the Random Forest parameters.")
    
    c_code = m2c.export_to_c(model)

    output_file = "results/iot_model.c"
    with open(output_file, "w") as f:
        f.write("#include <string.h>\n\n")
        f.write(c_code)

    print(f"[SUCCESS] Model successfully exported to '{output_file}'.")

if __name__ == "__main__":
    export_model()