FROM debian:latest

# install packages
RUN apt update
RUN apt install -y python3
RUN apt install -y python3-requests
RUN apt install -y curl

# Copy the Python script to the container
COPY docker-run.sh /root/
COPY task1/task1.py /root/
COPY task2/task2.py /root/
COPY task3_4/sniff_addresses.py /root/
COPY task3_4/task3.py /root/
COPY task3_4/task4.py /root/

# run when container starts
CMD ["bash", "/root/docker-run.sh"]