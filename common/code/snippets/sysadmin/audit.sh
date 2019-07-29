# Audit process syscalls (check exe=)

# (Default rates are 5)
sudo sysctl -w net.core.message_cost=0
sudo sysctl -w kernel.printk_ratelimit=0

sudo auditctl -a task,always -k shit
sudo auditctl -a exit,always -S open -k shit
