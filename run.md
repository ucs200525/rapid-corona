sudo -S rm -f data/blacklist.json

# Run the Application
## 1. Setup Virtual Network (veth pair)
```bash
# Create veth0 <-> veth1 pair
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
sudo ip addr add 192.168.99.1/24 dev veth0
sudo ip addr add 192.168.99.2/24 dev veth1
```

## 2. Start DDoS System (on veth1)
```bash
# Listen on veth1 (Ingress)
echo "password" | sudo -S python3 main.py --interface veth1 --mode generic --dashboard
```

## 3. Launch Attack (from veth0)
```bash
# Send spoofed packets from veth0 targeting veth1
sudo python3 attack_simulator.py --type mixed --distributed --source 100.100.100.100 --target 192.168.99.2 --duration 30 --interface veth0
```