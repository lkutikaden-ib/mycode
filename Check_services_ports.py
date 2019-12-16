"""
Status checks

"""

import json
import paramiko
import re
import yaml
import datetime
import requests
from subprocess import Popen, PIPE
from loggerinitializer import *
#from __future__ import print_function

initialize_logger('./logs')

#Function to execute ssh to jumphost
def execute_command(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd)
    cmd_output = stdout.read().decode()
    return cmd_output

#Function to execute os commands
def execute_os_command(cmd):
    try:
        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        assert not err, err
    except AssertionError as err:
        logging.error('ERROR:%s', err)
    return out

#Function to remove files 
def remove_file(telnet_file):
    remove_telnet_file_cmd = "rm -rf " + telnet_file
    execute_os_command(remove_telnet_file_cmd)

#Function to get count of instance
def get_instance_count(cluster_info):
    instance_count = {}
    polaris_count = len(re.findall("ssh_polaris*", cluster_info))
    instance_count['polaris'] = polaris_count
    cassandra_count = len(re.findall("ssh_cassandra*", cluster_info))
    instance_count['cassandra'] = cassandra_count
    indexer_count = len(re.findall("ssh_indexer*", cluster_info))
    instance_count['indexer'] = indexer_count
    jasper_count = len(re.findall("ssh_jasper*", cluster_info))
    instance_count['jasper'] = jasper_count
    load_balancer_count = len(re.findall("ssh_load_balancer*", cluster_info))
    instance_count['load_balancer'] = load_balancer_count
    memcache_ec_count = len(re.findall("ssh_memcache_ec*", cluster_info))
    instance_count['memcache'] = memcache_ec_count
    mira_count = len(re.findall("ssh_mira*", cluster_info))
    instance_count['mira'] = mira_count
    rds_polaris_count = len(re.findall("ssh_rds_polaris*", cluster_info))
    instance_count['rds_polaris'] = rds_polaris_count
    rds_rpt_count = len(re.findall("ssh_rds_rpt*", cluster_info))
    instance_count['rds_rpt'] = rds_rpt_count
    redis_count = len(re.findall("ssh_redis*", cluster_info))
    instance_count['redis'] = redis_count
    solr_count = len(re.findall("ssh_solr*", cluster_info))
    instance_count['solr'] = solr_count
    zookeeper_count = len(re.findall("ssh_zookeeper*", cluster_info))
    instance_count['zookeeper'] = zookeeper_count
    db_manager_count = len(re.findall("ssh_db_manager*", cluster_info))
    instance_count['db_manager'] = db_manager_count
    activemq_count = len(re.findall("ssh_activemq*", cluster_info))
    instance_count['activemq'] = activemq_count
    return instance_count

#function to print instance details
def display_instance_details(instance_count):
    print "\n"
    print "-------------------------------------------------------------------------------"
    print "The cluster Instance Details are:"
    print "Services          ", " Number of Instances"
    for k, v in instance_count.items():
        print '{0:20}  {1:10}'.format(k, v)
    print "-------------------------------------------------------------------------------"
    print "\n"
    return

#Function to check polaris for service and ports
def check_polaris(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking polaris" + str(index) + "............")

        status['instance' + str(index)] = "polaris" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "polaris"
        status['hostip' + str(index)] = "none"

        polaris_cmd = "ssh polaris" + str(index) + " 'sudo service polaris status'"
        #polaris_info = execute_command(client, polaris_cmd)
        polaris_info = execute_os_command(polaris_cmd)
        polaris_pid = re.findall(r'\d+', polaris_info)
        
        #get polaris_ip
        polaris_ip = "ssh polaris" + str(index) + " 'hostname -i'"
        #polaris_ip_info = execute_command(client,polaris_ip)
        polaris_ip_info = execute_os_command(polaris_ip)
        ip = polaris_ip_info.strip()
        status['hostip' + str(index)] = ip

        logging.info("Checking polaris" + str(index) + " Ports ............")
        polaris_port_cmd = "ssh polaris" + str(index) + " 'sudo netstat -apn  | grep -i listen | grep 8080| grep '" + \
                           polaris_pid[0]
        polaris_port_info = execute_os_command(polaris_port_cmd)
        if not (re.findall(str(polaris_pid[0]), polaris_port_info)):
            logging.error("Polaris is not running on the Port:8080")
            continue
        else:
            logging.info("Polaris PID is : %s", polaris_pid[0])
            logging.info("Polaris is running on the Port:8080")
            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(polaris_info)
            logging.info("Port Info:")
            logging.info(polaris_port_info)
            logging.info("-------------------------------------------------------------------------------")
        status['status' + str(index)] = "Running"
        status['port' + str(index)] = "8080"
    return status

#Function to check Mira for service and ports
def check_mira(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking Mira" + str(index) + " Service status............")
        status['instance' + str(index)] = "mira" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "mira"
        status['hostip' + str(index)] = "None"

        #get mira_ip
        mira_ip = "ssh mira" + str(index) + " 'hostname -i'"
        mira_ip_info = execute_os_command(mira_ip)
        ip = mira_ip_info.strip()
        status['hostip' + str(index)] = ip
         
        #check mira service status
        mira_cmd = "ssh mira" + str(index) + " 'sudo service mira status'"
        mira_info = execute_os_command(mira_cmd)
        mira_pid = re.findall(r'\d+', mira_info)

        logging.info("Checking Mira" + str(index) + " Ports ............")
        mira_port_cmd = "ssh mira" + str(index) + " 'sudo netstat -apn  | grep -i listen | grep 8080| grep '" + \
                        mira_pid[0]
        mira_port_info = execute_os_command(mira_port_cmd)
        if not (re.findall(str(mira_pid[0]), mira_port_info)):
            logging.error("Mira is not running on the Port:8080")
            continue
        else:
            logging.info("Mira PID is:%s", mira_pid[0])
            logging.info("Mira is running on the Port:8080")

        logging.info("Command output")
        logging.info("-------------------------------------------------------------------------------")
        logging.info("Service status:")
        logging.info(mira_info)
        logging.info("Port Info:")
        logging.info(mira_port_info)
        logging.info("-------------------------------------------------------------------------------")
        status['status' + str(index)] = "Running"
        status['port' + str(index)] = "8080"
    return status

#Function to check jasper for service and ports status
def check_jasper(value):
    status = {}
    jasper_pid = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking Jasper" + str(index) + "............")
        status['instance' + str(index)] = "jasper" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "jasper"
        status['hostip' + str(index)] = "None"
        
        #get jasper_ip
        jasper_ip = "ssh jasper" + str(index) + " 'hostname -i'"
        jasper_ip_info = execute_os_command(jasper_ip)
        ip = jasper_ip_info.strip()
        status['hostip' + str(index)] = ip

        #jasper_cmd = "ssh jasper" + str(index) + " 'sudo service jasper status'"
        jasper_cmd = "ssh jasper" + str(index) + " 'sudo ps aux|grep -v grep|grep /mobileiron.com/programs/com.mobileiron.jre/bin/java'"
        jasper_info = execute_os_command(jasper_cmd)
        jasper_pid = re.findall(r'\d+', jasper_info) 
        if not jasper_pid:
            logging.error("Jasper service not found to be running in jasper" + str(index))
            continue
        else:
            logging.info("info :%s", jasper_info)
            logging.info("PID : %s", jasper_pid[1])

            logging.info("Checking Jasper" + str(index) + " Ports ............")
            jasper_port_cmd = "ssh jasper" + str(index) + " 'sudo netstat -apn  | grep -i listen \
            | grep 8080| grep '" + jasper_pid[1]
            jasper_port_info = execute_os_command(jasper_port_cmd)
            if not (re.findall(str(jasper_pid[1]), jasper_port_info)):
                logging.error("Jasper is not running on the Port:8080")
                continue
            else:
                logging.info("Jasper PID is :%s", jasper_pid[1])
                logging.info("Jasper is running on the Port:8080")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(jasper_info)
            logging.info("Port Info:")
            logging.info(jasper_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "8080"
    return status

#Function to check redis for service and ports status
def check_redis(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking redis" + str(index) + "............")
        status['instance' + str(index)] = "redis" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "redis"
        status['hostip' + str(index)] = "None" 
    
        #get redis_ip
        redis_ip = "ssh redis" + str(index) + " 'hostname -i'"
        redis_ip_info = execute_os_command(redis_ip)
        ip = redis_ip_info.strip()
        status['hostip' + str(index)] = ip        

        redis_cmd = "ssh redis" + str(index) + " 'sudo service redis status'"
        redis_info = execute_os_command(redis_cmd)
        redis_text = re.findall("Redis", redis_info)
        if not redis_text:
            logging.error("Redis service not found to be running in redis1")
            continue
        else:
            redis_pid_cmd = "ssh redis" + str(index) + " 'sudo ps -ef | grep redis | grep 6379' "
            redis_pid_info = execute_os_command(redis_pid_cmd)
            redis_pid_all = re.findall(r"redis\s*(\d+)", redis_pid_info)
            redis_pid = redis_pid_all[0]
            logging.info("Redis PID is :%s", redis_pid)
            logging.info("Checking redis" + str(index) + " Ports ............")
            redis_port_cmd = "ssh redis" + str(
                index) + " 'sudo netstat -apn  | grep -i LISTEN | grep 6379| grep '" + redis_pid
            redis_port_info = execute_os_command(redis_port_cmd)
            if not (re.findall(str(redis_pid), redis_port_info)):
                logging.error("Redis is not running on the Port:6379")
                continue
            else:
                logging.info("Redis is running on the Port:6379")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(redis_info)
            logging.info("Port Info:")
            logging.info(redis_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "6379"
    return status

#Function to check active mq for service and ports status
def check_activemq(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking Activemq" + str(index) + "............")
        status['instance' + str(index)] = "activemq" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "activemq"
        status['hostip' + str(index)] = "None"

        #get activemq_ip
        activemq_ip = "ssh activemq" + str(index) + " 'hostname -i'"
        activemq_ip_info = execute_os_command(activemq_ip)
        ip = activemq_ip_info.strip()
        status['hostip' + str(index)] = ip

        activemq_cmd = "ssh activemq" + str(index) + " 'sudo service activemq status |grep ActiveMQ'"
        activemq_info = execute_os_command( activemq_cmd)
        activemq_pid_all = re.findall(r"pid\s*\'(\d+)\'", activemq_info)
        if not activemq_pid_all:
            logging.error("Activemq service not found to be running in Activemq" + str(index))
            continue
        else:
            activemq_pid = activemq_pid_all[0]
            logging.info("Activemq PID is: %s", activemq_pid)

            logging.info("Checking activemq" + str(index) + " Ports ............")
            activemq_port_cmd = "ssh activemq" + str(
                index) + " 'sudo netstat -apn  | grep -i listen | grep 61616| grep '" + activemq_pid
            activemq_port_info = execute_os_command(activemq_port_cmd)
            if not (re.findall(str(activemq_pid), activemq_port_info)):
                logging.info("Activemq is not running on the Port:61616")
                break
            else:
                logging.info("Activemq is running on the Port:61616")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(activemq_info)
            logging.info("Port Info:")
            logging.info(activemq_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "61616"
    return status

#Function to check cassandra for service and ports status
def check_cassandra(value):
    status = {}
    for index in range(1, int(value) + 1):
        status['instance' + str(index)] = "cassandra" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "cassandra"
        status['hostip' + str(index)] = "None"

        #get cassandra_ip
        cassandra_ip = "ssh cassandra" + str(index) + " 'hostname -i'"
        cassandra_ip_info = execute_os_command(cassandra_ip)
        ip = cassandra_ip_info.strip()
        status['hostip' + str(index)] = ip      

        logging.info("Checking cassandra" + str(index) + "............")
        cassandra_cmd = "ssh cassandra" + str(index) + " 'sudo service cassandra status'"
        cassandra_info = execute_os_command( cassandra_cmd)
        cassandra_pid = re.findall(r'\d+', cassandra_info)
        if not cassandra_pid:
            logging.error("cassandra service not found to be running in cassandra" + str(index))
            continue
        else:
            logging.info(cassandra_info.strip())
            logging.info("cassandra PID is :%s", cassandra_pid[0])

            logging.info("Checking cassandra" + str(index) + " Ports ............")
            cassandra_port_cmd = "ssh cassandra" + str(
                index) + " 'sudo netstat -apn  | grep -i listen | grep 9042| grep '" + cassandra_pid[0]
            cassandra_port_info = execute_os_command(cassandra_port_cmd)
            if not (re.findall(str(cassandra_pid[0]), cassandra_port_info)):
                logging.error("cassandra is not running on the Port:9042")
                continue
            else:
                logging.info("cassandra is running on the Port:9042")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(cassandra_info)
            logging.info("Port Info:")
            logging.info(cassandra_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "9042"
    return status

#Function to solr jasper for service and ports status
def check_solr(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking solr" + str(index) + "............")
        status['instance' + str(index)] = "solr" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "solr"
        status['hostip' + str(index)] = "None"

        #get solr_ip
        solr_ip = "ssh solr" + str(index) + " 'hostname -i'"
        solr_ip_info = execute_os_command(solr_ip)
        ip = solr_ip_info.strip()
        status['hostip' + str(index)] = ip

        solr_cmd = "ssh solr" + str(index) + " 'sudo service solr status'"
        solr_info = execute_os_command(solr_cmd)
        solr_pid = re.findall(r'\d+', solr_info)
        if not solr_pid:
            logging.error("solr service not found to be running in solr" + str(index))
            continue
        else:
            logging.info(solr_info.strip())
            logging.info("solr PID is :%s", solr_pid[0])

            logging.info("Checking solr" + str(index) + " Ports ............")
            solr_port_cmd = "ssh solr" + str(index) + " 'sudo netstat -apn  | grep -i listen | grep 9000' "
            solr_port_info = execute_os_command(solr_port_cmd)
            if not (re.findall(str(solr_pid[0]), solr_port_info)):
                logging.error("solr is not running on the Port:9042")
                continue
            else:
                logging.info("solr is running on the Port:9042")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(solr_info)
            logging.info("Port Info:")
            logging.info(solr_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "9000"
    return status

#Function to check indexer for service and ports status
def check_indexer(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking indexer" + str(index) + "............")

        status['instance' + str(index)] = "indexer" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "indexer"
        status['hostip' + str(index)] = "None"

        #get indexer_ip
        indexer_ip = "ssh indexer" + str(index) + " 'hostname -i'"
        indexer_ip_info = execute_os_command(indexer_ip)
        ip = indexer_ip_info.strip()
        status['hostip' + str(index)] = ip

        indexer_cmd = "ssh indexer" + str(index) + " 'sudo service audittrails-indexer status'"
        indexer_info = execute_os_command(indexer_cmd)
        indexer_text = re.findall(r'indexer', indexer_info)
        if not indexer_text:
            logging.error("Indexer service not found to be running in indexer" + str(index))
            continue
        else:
            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(indexer_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
    return status

#Function to check load_balancer for service and ports status
def check_load_balancer(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking load_balancer" + str(index) + "............")
        status['instance' + str(index)] = "load_balancer" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "httpd/haproxy"
        status['hostip' + str(index)] = "None"

        #get load_balancer_ip
        load_balancer_ip = "ssh load_balancer" + str(index) + " 'hostname -i'"
        load_balancer_ip_info = execute_os_command(load_balancer_ip)
        ip = load_balancer_ip_info.strip()
        status['hostip' + str(index)] = ip

        load_balancer_haproxy_cmd = "ssh load_balancer" + str(index) + " 'ps -ef |grep ^haproxy'"
        load_balancer_haproxy_info = execute_os_command(load_balancer_haproxy_cmd)
        load_balancer_httpd_cmd = "ssh load_balancer" + str(index) + " 'ps -ef |grep httpd|grep ^root'"
        load_balancer_httpd_info = execute_os_command(load_balancer_httpd_cmd)
        load_balancer_haproxy_pid = re.findall(r'haproxy\s*(\d+)', load_balancer_haproxy_info)
        load_balancer_httpd_pid = re.findall(r'root\s*(\d+)', load_balancer_httpd_info)
        if not (load_balancer_httpd_pid and load_balancer_haproxy_pid):
            logging.error("Load_balancer service not found to be running in load_balancer" + str(index))
            continue
        else:
            logging.info("Load_balancer httpd PID is :%s", load_balancer_httpd_pid[0])
            logging.info("Load_balancer haproxy PID is :%s", load_balancer_haproxy_pid[0])

            logging.info("Checking Load_balancer" + str(index) + " Ports ............")
            load_balancer_haproxy_port_cmd = "ssh load_balancer" + str(
                index) + " 'sudo netstat -apn  | grep -i listen | grep '" + load_balancer_haproxy_pid[0]
            load_balancer_haproxy_port_info = execute_os_command( load_balancer_haproxy_port_cmd)
            load_balancer_httpd_port_cmd = "ssh load_balancer" + str(
                index) + " 'sudo netstat -apn  | grep -i listen | grep '" + load_balancer_httpd_pid[0]
            load_balancer_httpd_port_info = execute_os_command(load_balancer_httpd_port_cmd
                                                            )
            load_balancer_haproxy_port_check = re.findall(str(load_balancer_haproxy_pid[0]),
                                                          load_balancer_haproxy_port_info)
            load_balancer_httpd_port_check = re.findall(str(load_balancer_httpd_pid[0]), load_balancer_httpd_port_info)
            if not (load_balancer_haproxy_port_check and load_balancer_httpd_port_check):
                logging.error("Load_balancer is not running on the Ports:443|80|5000|8883")
                continue
            else:
                logging.info("load_balancer httpd is running on the Port:443,80")
                logging.info("load_balancer haproxy is running on the Port:5000,8883")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(load_balancer_haproxy_info)
            logging.info(load_balancer_httpd_info)
            logging.info("Port Info:")
            logging.info(load_balancer_haproxy_port_info)
            logging.info(load_balancer_httpd_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "443,80/5000,8883"
    return status

#Function to check zookeper for service and ports status
def check_zookeeper(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking zookeeper" + str(index) + "............")
        status['instance' + str(index)] = "zookeeper" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "zookeeper/kafka"
        status['hostip' + str(index)] = "None"

        #get zookeeper_ip
        zookeeper_ip = "ssh zookeeper" + str(index) + " 'hostname -i'"
        zookeeper_ip_info = execute_os_command(zookeeper_ip)
        ip = zookeeper_ip_info.strip()
        status['hostip' + str(index)] = ip
 
        zookeeper_cmd = "ssh zookeeper" + str(index) + " 'ps -ef |grep zookeeper|grep mobileiron-zookeeper.conf$'"
        zookeeper_info = execute_os_command( zookeeper_cmd)
        kafka_cmd = "ssh zookeeper" + str(index) + " 'ps -ef |grep zookeeper|grep mobileiron-kafka.conf$'"
        kafka_info = execute_os_command(kafka_cmd)
        zookeeper_pid = re.findall(r'root\s*(\d+)', zookeeper_info)
        kafka_pid = re.findall(r'root\s*(\d+)', kafka_info)
        if not (zookeeper_pid and kafka_pid):
            logging.error("Zookeeper/Kafka service not found to be running in zookeeper" + str(index))
            continue
        else:
            logging.info("zookeper PID is :%s", zookeeper_pid[0])
            logging.info("kafka PID is :%s", kafka_pid[0])

            logging.info("Checking Zookeeper" + str(index) + " Ports ............")
            zookeeper_port_cmd = " ssh zookeeper" + str(
                index) + " 'sudo netstat -apn  | grep -i listen| grep 2181 |grep '" + zookeeper_pid[0]
            zookeeper_port_info = execute_os_command(zookeeper_port_cmd)
            kafka_port_cmd = "ssh zookeeper" + str(index) + " 'sudo netstat -apn  | grep -i listen \
            | grep 9092|grep '" + kafka_pid[0]
            kafka_port_info = execute_os_command(kafka_port_cmd
                                              )
            zookeeper_port_check = re.findall(str(zookeeper_pid[0]), zookeeper_port_info)
            kafka_port_check = re.findall(str(kafka_pid[0]), kafka_port_info)
            if not (zookeeper_port_check and kafka_port_check):
                logging.error("Zookeeper/kafka is not running on the Ports:2181/9092")
                continue
            else:
                logging.info("Zookeeper is running on the Port:2181")
                logging.info("Kafka is running on the Port:9092")

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info("Service status:")
            logging.info(zookeeper_info)
            logging.info(kafka_info)
            logging.info("Port Info:")
            logging.info(zookeeper_port_info)
            logging.info(kafka_port_info)
            logging.info("-------------------------------------------------------------------------------")
            status['status' + str(index)] = "Running"
            status['port' + str(index)] = "2181/9092"
    return status

#Function to check memcache for service and ports status
def check_memcache(value):
    status = {}
    for index in range(1, int(value) + 1):
        logging.info("Checking polaris" + str(index) + " for memcache............")

        status['instance' + str(index)] = "memcache" + str(index)
        status['port' + str(index)] = "None"
        status['status' + str(index)] = "Not Running"
        status['service' + str(index)] = "memcache"
        status['hostip' + str(index)] = "None"
        

        # Get details of Memcache host and port from Polaris1
        memcache_cmd = "ssh polaris" + str(
            index) + " 'cat /mobileiron.com/data/polaris/polaris.properties | grep memcache'"
        memcache_info = execute_os_command(memcache_cmd)
        if not memcache_info:
            logging.error("Memcache server not found to be running in polaris" + str(index))
            continue
        else:
            memcache_server = memcache_info.split(":")
            memcache_server_name = memcache_server[0].split("=")
            memcache_server_port = memcache_server[1].strip('\n')

            # create python program with memcache host an port to execute in polaris1
            telnet_array = ["import telnetlib",
                            "host = '" + memcache_server_name[1] + "'",
                            "port = " + memcache_server_port,
                            "tn = telnetlib.Telnet(host,port)",
                            "tn.write('stats\\n')",
                            "tn.write('exit\\n')",
                            "tn.write('quit\\n')",
                            "print tn.read_all()",
                            "tn.close()"]

            now = datetime.datetime.now().strftime("%y-%m-%d-%H-%M")
            telnet_file = "/tmp/telnet_cmd_" + str(now) + ".py"
            fh = open(telnet_file, "w")
            string_1 = "\n".join(telnet_array)
            fh.write(string_1)
            fh.close()
               
            #copy telent file to polaris1
            copy_file = "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q " \
                         + telnet_file + " polaris1:/tmp"
            execute_os_command(copy_file)
            execute_telnet_file = "ssh polaris" + str(index) + " 'python " + telnet_file + "'"
                
            execute_telnet_file_info = execute_os_command(execute_telnet_file)
            memcache_stat = re.findall(r'STAT *', execute_telnet_file_info)
            if not memcache_stat:
                logging.error("-------------------------------------------------------------------------------")
                logging.error("Memcache service is not up in polaris" + str(index))
                logging.error("-------------------------------------------------------------------------------")
                logging.error("\n")
                continue
            else:

                logging.info("Command output")
                logging.info("-------------------------------------------------------------------------------")
                logging.info("Service status:")
                logging.info(execute_telnet_file_info)
                logging.info("-------------------------------------------------------------------------------")
                status['status' + str(index)] = "Running"
                remove_file(telnet_file)
    return status

#Function to check leo for service and ports status
def check_leo():
    status = {'status'  : 'Not Running', 
              'instance': 'leo', 
              'port'    : 'None', 
              'service' : 'leo',
              'hostip'  : 'none'
             }

    logging.info("Checking leo")
    input_data = get_input()
    cluster_name = input_data['leo_cluster_name']
 

    url = "https://%s/status" % cluster_name
    response = requests.get(url).text
    leo_info = re.findall(r'MOBILEIRON-STATUS: OK', response)
    if not leo_info:
        logging.info("Leo is not running")
    else:

        logging.info("Command output")
        logging.info("-------------------------------------------------------------------------------")
        logging.info('MOBILEIRON-STATUS: OK')
        logging.info("-------------------------------------------------------------------------------")
        status['status'] = "Running"
    return status

#Function to check capella for service and ports status
def check_capella():
    status = {'status'  : 'Not Running', 
              'instance': 'capella', 
              'port'    : 'None', 
              'service' : 'capella',
              'hostip'  : 'None'
             }

    logging.info("Checking Capella")
    input_data = get_input()
    cluster_name = input_data['capella_cluster_name']
    url = "https://%s/status" % cluster_name
    response = requests.get(url).text
    capella_info = re.findall(r'MOBILEIRON-STATUS: OK', response)
    if not capella_info:
        logging.error("capella is not running")
    else:

        logging.info("Command output")
        logging.info("-------------------------------------------------------------------------------")
        logging.info('MOBILEIRON-STATUS: OK')
        logging.info("-------------------------------------------------------------------------------")
        status['status'] = "Running"
    return status

#Function to get status and print
def check_services(count):
    # print(count)
    status_polaris = None
    status_mira = None
    status_jasper = None
    status_redis = None
    status_activemq = None
    status_cassandra = None
    status_indexer = None
    status_lb = None
    status_memcache = None
    status_zk = None
    status_solr = None
    for key, value in count.items():
        if key == "polaris":
            status_polaris = check_polaris(value)
        if key == "mira":
            status_mira = check_mira(value)
        if key == "jasper":
            status_jasper = check_jasper(value)
        if key == "redis":
            status_redis = check_redis(value)
        if key == "activemq":
            status_activemq = check_activemq(value)
        if key == "cassandra":
            status_cassandra = check_cassandra(value)
        if key == "indexer":
            status_indexer = check_indexer(value)
        if key == "load_balancer":
            status_lb = check_load_balancer(value)
        if key == "memcache":
            status_memcache = check_memcache(value)
        if key == "zookeeper":
            status_zk = check_zookeeper(value)
        if key == "solr":
            status_solr = check_solr(value)
    status_leo = check_leo()
    status_capella = check_capella()

    print "\n"
    print "-----------------------------------------------------------------------------------"
    print "The Service and Port Details are:"
    print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format("Instance", "IP","Services", "Status", "Port")
    for index in range(1, int(count['polaris']) + 1):
        print "{0:20}  {1:20} {2:20} {3:20} {4:20}".format(
                                                            status_polaris["instance" + str(index)], 
                                                            status_polaris["hostip" + str(index)], 
                                                            status_polaris["service" + str(index)],
                                                            status_polaris["status" + str(index)], 
                                                            status_polaris["port" + str(index)]
                                                           )
    for index in range(1, int(count['cassandra']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                             status_cassandra["instance"+str(index)], 
                                                             status_cassandra["hostip"+str(index)], 
                                                             status_cassandra["service"+str(index)],
                                                             status_cassandra["status" + str(index)], 
                                                             status_cassandra["port"+str(index)]
                                                          )
    for index in range(1, int(count['jasper']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_jasper["instance"+str(index)],
                                                            status_jasper["hostip"+str(index)],
                                                            status_jasper["service"+str(index)],
                                                            status_jasper["status" + str(index)],
                                                            status_jasper["port"+str(index)])
    for index in range(1, int(count['mira']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_mira["instance"+str(index)], 
                                                            status_mira["hostip"+str(index)], 
                                                            status_mira["service"+str(index)],
                                                            status_mira["status" + str(index)], 
                                                            status_mira["port"+str(index)]
                                                          )
    for index in range(1, int(count['redis']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_redis["instance"+str(index)], 
                                                            status_redis["hostip"+str(index)], 
                                                            status_redis["service"+str(index)],
                                                            status_redis["status" + str(index)], 
                                                            status_redis["port"+str(index)]
                                                          )
    for index in range(1, int(count['activemq']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_activemq["instance"+str(index)], 
                                                            status_activemq["hostip"+str(index)], 
                                                            status_activemq["service"+str(index)],
                                                            status_activemq["status"+str(index)], 
                                                            status_activemq["port"+str(index)]
                                                          )
    for index in range(1, int(count['solr']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_solr["instance"+str(index)], 
                                                            status_solr["hostip"+str(index)], 
                                                            status_solr["service"+str(index)],
                                                            status_solr["status" + str(index)], 
                                                            status_solr["port"+str(index)]
                                                          )
    for index in range(1, int(count['indexer']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_indexer["instance"+str(index)], 
                                                            status_indexer["hostip"+str(index)], 
                                                            status_indexer["service"+str(index)],
                                                            status_indexer["status" + str(index)], 
                                                            status_indexer["port"+str(index)]
                                                          )
    for index in range(1, int(count['load_balancer']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_lb["instance"+str(index)], 
                                                            status_lb["hostip"+str(index)], 
                                                            status_lb["service"+str(index)],
                                                            status_lb["status" + str(index)], 
                                                            status_lb["port"+str(index)]
                                                         )
    for index in range(1, int(count['zookeeper']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                           status_zk["instance"+str(index)], 
                                                           status_zk["hostip"+str(index)], 
                                                           status_zk["service"+str(index)],
                                                           status_zk["status" + str(index)], 
                                                           status_zk["port"+str(index)]
                                                          )
    for index in range(1, int(count['memcache']) + 1):
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                           status_memcache["instance"+str(index)], 
                                                           status_memcache["hostip"+str(index)], 
                                                           status_memcache["service"+str(index)],
                                                           status_memcache["status" + str(index)], 
                                                           status_memcache["port"+str(index)]
                                                          )
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                           status_leo["instance"], 
                                                           status_leo["hostip"], 
                                                           status_leo["service"],
                                                           status_leo["status"], 
                                                           status_leo["port"]
                                                          )
        print '{0:20}  {1:20} {2:20} {3:20} {4:20}'.format(
                                                            status_capella["instance"], 
                                                            status_capella["hostip"], 
                                                            status_capella["service"],
                                                            status_capella["status"], 
                                                            status_capella["port"]
                                                          )

    print "-----------------------------------------------------------------------------------"
    print "\n"

#function to get input from yaml files
def get_input():
    input_data = {}
    file_name = 'Check_services_ports.yaml'

    with open(file_name) as infile:
        data = yaml.load(infile)
    input_data['pem_location'] = data['pem_location']
    input_data['pem_file_name'] = data['pem_file_name']
    input_data['jump_host'] = data['jump_host_name']
    input_data['user'] = data['jump_host_user']
    input_data['leo_cluster_name'] = data['leo_cluster_domain_name']
    input_data['capella_cluster_name'] = data['capella_cluster_domain_name']
    input_data['polaris_cluster_name'] = data['polaris_cluster_domain_name']
    return input_data

#Function to check reachability of services from polaris
def check_polaris_service(service):
    status = {'status': 'Not Reachable', 'return_code': 'None', 'service': service}
    logging.info("Checking from polaris the service: %s", service)
    input_data = get_input()
    cluster_name = input_data['polaris_cluster_name']
    url = "https://%s/status/%s" % (cluster_name, service)
    return_value = requests.get(url, auth=("polaris@mobileiron.com", "polaris123"))
    if not return_value.ok:
        logging.error("%s" + service + "  is not reachable from polaris")
    else:
	response = return_value.text
        data = return_value.json()
        polaris_service_info = re.findall(r'MOBILEIRON-STATUS:\s(\w+)', response)
        polaris_service_stat_code = data["result"]["statusCode"]
        polaris_service_stat = polaris_service_info[0]
        status['return_code'] = polaris_service_stat_code
        logging.info('status: %s', data["result"]["status"])
        status['status'] = data["result"]["status"]
        if polaris_service_stat == "ERROR":
            logging.error("%s" + service + "  is not reachable from polaris")
        else:

            logging.info("Command output")
            logging.info("-------------------------------------------------------------------------------")
            logging.info('MOBILEIRON-STATUS: OK')
            logging.info("-------------------------------------------------------------------------------")
    return status

#Function to check all services from polaris
def check_polaris_services():
    service_status = {}
    services = ["ara", "apns", "hoedus", "reportingdb",
                "db", "leo", "jasperserver", "capella",
                "solr", "redis", "velareg", "mira",
                "cassandra"]
    for service in services:
        # servicestat = 'service_' + service
        servicestat = check_polaris_service(service)
        service_status[service] = servicestat

    display_polaris_services_details(service_status)

#Function to display the Polaris sercive reachability status
def display_polaris_services_details(services_stat):
    print "\n"
    print "-------------------------------------------------------------------------------"
    print "Polaris service status are:"
    print "{0:20}  {1:30}   {2:10}".format("Services", "Status", "Returncode")
    # print(f'{"Services":20}  {"Status":30}   {"Returncode":10}')
    for k, v in services_stat.items():
        status = v["status"]
        rcode = v["return_code"]
        print "{0:20}  {1:30}   {2:10}".format(str(k), str(status), str(rcode))
    # print(f'{str(k):20}  {str(status):30}   {str(rcode):10}')
    print "-------------------------------------------------------------------------------"
    print "\n"

#Main Function
def main():

    # Execute a command(cmd) to get the instance details
    polaris_cmd = "cat /mobileiron.com/users/operations/.bash_profile"
    cluster_info = execute_os_command(polaris_cmd)

    instance_count = get_instance_count(cluster_info)

    check_services(instance_count)
    check_polaris_services()

    display_instance_details(instance_count)



if __name__ == "__main__":
    main()
