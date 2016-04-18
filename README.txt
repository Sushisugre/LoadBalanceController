

# Launch controller
./pox.py log.level --DEBUG load_balancer --balancer_addr=10.0.0.254 --server_addrs=10.0.0.1,10.0.0.2,10.0.0.3

# Setup Network
sudo mn --topo single,10 --mac --arp --switch ovsk --controller remote

# Launch Servers
h1 python -m SimpleHTTPServer 80 &
h2 python -m SimpleHTTPServer 80 &
h3 python -m SimpleHTTPServer 80 &

# Sending request to load balancer
h4 wget -O - 10.0.0.254




