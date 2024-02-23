cd build
tar cvfz bin.tgz bin lib

# In this example:
# pufse host locates in 172.16.1.94 port 22104
# The user should modify the scp address/port to meet your environment.

scp -P 22104 bin.tgz root@172.16.1.94:/home/root/aws/awsiot
