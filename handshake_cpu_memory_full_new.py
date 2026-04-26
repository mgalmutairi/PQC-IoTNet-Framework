import os
import subprocess
import paho.mqtt.client as mqtt
import time
import csv
import ssl
import sys
import threading
import psutil

# --- CONFIGURATION ---
print(f"--- Starting experiment (Single Scenario) ---")
print(f"Python SSL Version: {ssl.OPENSSL_VERSION}")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CERT_MAP = {
    "ECC-P256": os.path.join(BASE_DIR, "broker_cert.pem"),
    "RSA-2048": os.path.join(BASE_DIR, "broker_rsa_cert.pem"),
    "CRYSTALS-Kyber": os.path.join(BASE_DIR, "broker_cert.pem"),
}

EXPERIMENTS = {
    "ECC-P256": "prime256v1",
    "RSA-2048": None,
    "CRYSTALS-Kyber": None
}

# --- MULTIPLE NETWORK SCENARIOS ---
LATENCIES = [0, 50, 100, 300, 500]
PACKET_LOSS = [0, 2, 5, 10]
SCENARIOS = [(lat, loss) for lat in LATENCIES for loss in PACKET_LOSS]

NUM_RUNS = 50

BROKER_HOST = "localhost"
BROKER_PORT = 8883


# --- NETWORK CONTROL ---
def setup_network_conditions(latency_ms, loss_percent):
    subprocess.run("sudo tc qdisc del dev lo root", shell=True, check=False, stderr=subprocess.DEVNULL)
    if latency_ms > 0 or loss_percent > 0:
        subprocess.run(
            f"sudo tc qdisc add dev lo root netem delay {latency_ms}ms loss {loss_percent}%",
            shell=True,
            check=True
        )

def reset_network_conditions():
    subprocess.run("sudo tc qdisc del dev lo root", shell=True, check=False, stderr=subprocess.DEVNULL)


# --- SINGLE TRIAL WITH BANDWIDTH ---
def run_single_trial(algorithm_name):

    if not os.path.exists(CERT_MAP[algorithm_name]):
        return {
            "handshake_time_ms": 0,
            "cpu_time_ms": 0,
            "memory_peak_mb": 0,
            "memory_delta_mb": 0,
            "bytes_transmitted": 0,
            "was_successful": 0,
            "error": "Certificate file not found"
        }

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if algorithm_name == "RSA-2048":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers("AES256-SHA")
    elif algorithm_name == "ECC-P256":
        context.set_ciphers("ECDHE-ECDSA-AES256-GCM-SHA384")
        context.set_ecdh_curve("prime256v1")
    elif algorithm_name == "CRYSTALS-Kyber":
        pass  # Requires OpenSSL + OQS

    context.load_verify_locations(cafile=CERT_MAP[algorithm_name])
    client.tls_set_context(context)
    client.tls_insecure_set(True)

    process = psutil.Process(os.getpid())
    connected_event = threading.Event()
    error_msg = "None"
    was_successful = 0

    # --- MQTT callbacks ---
    def on_connect(client, userdata, flags, rc, properties=None):
        nonlocal error_msg
        if rc == 0:
            connected_event.set()
        else:
            error_msg = f"Connection failed with code {rc}"
            connected_event.set()

    client.on_connect = on_connect

    try:
        # --- CPU & Memory ---
        cpu_before = process.cpu_times()
        mem_before = process.memory_info().rss
        peak_memory = mem_before

        # --- Bandwidth (loopback interface) ---
        net_before = psutil.net_io_counters(pernic=True)['lo']
        bytes_before = net_before.bytes_sent + net_before.bytes_recv

        # --- Handshake timer ---
        start_time = time.monotonic()

        client.connect(BROKER_HOST, BROKER_PORT, 60)
        client.loop_start()

        timeout = 10.0
        wait_start = time.monotonic()

        while True:
            if connected_event.is_set():
                break

            current_mem = process.memory_info().rss
            if current_mem > peak_memory:
                peak_memory = current_mem

            if time.monotonic() - wait_start > timeout:
                error_msg = "Connection timeout"
                break

            time.sleep(0.01)

        end_time = time.monotonic()

        # --- CPU ---
        cpu_after = process.cpu_times()
        user_cpu = cpu_after.user - cpu_before.user
        system_cpu = cpu_after.system - cpu_before.system
        cpu_time_ms = (user_cpu + system_cpu) * 1000

        if error_msg == "None":
            was_successful = 1

        # --- Memory ---
        memory_peak_mb = peak_memory / (1024 * 1024)
        memory_delta_mb = (peak_memory - mem_before) / (1024 * 1024)

        # --- Bandwidth ---
        net_after = psutil.net_io_counters(pernic=True)['lo']
        bytes_sent = net_after.bytes_sent - net_before.bytes_sent
        bytes_recv = net_after.bytes_recv - net_before.bytes_recv
        total_bytes = bytes_sent + bytes_recv

    except Exception as e:
        end_time = time.monotonic()
        cpu_time_ms = 0
        memory_peak_mb = 0
        memory_delta_mb = 0
        total_bytes = 0
        error_msg = str(e)

    finally:
        client.loop_stop()
        client.disconnect()

    handshake_time_ms = (end_time - start_time) * 1000 if was_successful else 0

    return {
        "handshake_time_ms": handshake_time_ms,
        "cpu_time_ms": cpu_time_ms,
        "memory_peak_mb": memory_peak_mb,
        "memory_delta_mb": memory_delta_mb,
        "bytes_transmitted": total_bytes,
        "was_successful": was_successful,
        "error": error_msg
    }
# --- MAIN ---
def main():
    all_results = []

    try:
        subprocess.run("sudo -v", shell=True, check=True)
    except Exception as e:
        print(f"Could not get sudo permissions: {e}")
        sys.exit(1)

    try:
        for lat, loss in SCENARIOS:
            setup_network_conditions(lat, loss)
            
            for algo_name in EXPERIMENTS.keys():
                 print(f"\n--- Testing: Algorithm={algo_name}, Latency={lat}ms, Loss={loss}% ---")
                 
                 for i in range(NUM_RUNS):
                    print(f"Run {i+1}/{NUM_RUNS}...", end=" ", flush=True)

                    result = run_single_trial(algo_name)

                    if result["was_successful"]:
                        print(
                            f"Handshake: {result['handshake_time_ms']:.2f} ms | "
                            f"CPU: {result['cpu_time_ms']:.2f} ms | "
                            f"Mem Peak: {result['memory_peak_mb']:.2f} MB"
                        )
                    else:
                        print(f"FAILED ({result['error']})")

                    all_results.append({
                        "algorithm": algo_name,
                        "latency_ms": lat,
                        "packet_loss_percent": loss,
                        "run_number": i + 1,
                        "handshake_time_ms": result["handshake_time_ms"],
                        "cpu_time_ms": result["cpu_time_ms"],
                        "memory_peak_mb": result["memory_peak_mb"],
                        "memory_delta_mb": result["memory_delta_mb"],
                        "bytes_transmitted": result["bytes_transmitted"],
                        "was_successful": result["was_successful"],
                        "error_msg": result["error"]
                        

                    })
    except Exception as e:
        print(f"\nUnexpected error: {e}")


    finally:
        reset_network_conditions()

        if not all_results:
            print("No results to write.")
            return

        csv_file = os.path.join(BASE_DIR, "scenario_results_new.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_results[0].keys())
            writer.writeheader()
            writer.writerows(all_results)

        print(f"\nResults saved to {csv_file}")


if __name__ == "__main__":
    main()
